package main

import (
	"database/sql"
	"log"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"
	_ "github.com/lib/pq"
	"golang.org/x/crypto/bcrypt"
)

type Asset struct {
	ID        int    `json:"id"`
	Name      string `json:"name"`
	Category  string `json:"category"`
	IPAddress string `json:"ip_address"`
	Status    string `json:"status"`
}

type User struct {
	ID       int    `json:"id"`
	Name     string `json:"name"`
	Email    string `json:"email"`
	Password string `json:"password,omitempty"`
	Role     string `json:"role"`
}

type LogEntry struct {
	ID        int    `json:"id"`
	Action    string `json:"action"`
	UserEmail string `json:"user_email"`
	IPAddress string `json:"ip_address"`
	Timestamp string `json:"timestamp"`
}

var jwtKey = []byte("assetflow_super_secret_key_2026")
var db *sql.DB

func main() {
	connStr := os.Getenv("DATABASE_URL")
	if connStr == "" {
		log.Println("⚠️ Warning: DATABASE_URL tidak diset, menggunakan string koneksi default")
	}

	var err error
	db, err = sql.Open("postgres", connStr)
	if err != nil {
		log.Fatal("🚨 Gagal membuka koneksi database: ", err)
	}
	defer db.Close()

	// Tes koneksi database
	if err = db.Ping(); err != nil {
		log.Fatal("🚨 Password Supabase salah atau Database mati: ", err)
	}

	r := gin.Default()
	r.Use(CORSMiddleware())

	// ==========================================
	// TAMBAHAN: Menyajikan file index.html di root
	// ==========================================
	r.GET("/", func(c *gin.Context) {
		c.File("index.html")
	})

	api := r.Group("/api/v1")
	{
		api.POST("/register", registerUser)
		api.POST("/login", loginUser)

		protected := api.Group("/")
		protected.Use(AuthMiddleware()) 
		{
			protected.GET("/assets", getAssets)
			protected.POST("/assets", createAsset)
			protected.PUT("/assets/:id", updateAsset)
			protected.DELETE("/assets/:id", deleteAsset)
			protected.GET("/logs", getLogs)
			protected.GET("/users", getUsers)
		}
	}

	log.Println("🚀 Enterprise Backend berjalan di http://localhost:8080")
	r.Run(":8080")
}

func registerUser(c *gin.Context) {
	var user User
	if err := c.ShouldBindJSON(&user); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Data form tidak valid"})
		return
	}

	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(user.Password), bcrypt.DefaultCost)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Gagal enkripsi password"})
		return
	}

	query := `INSERT INTO users (name, email, password, role) VALUES ($1, $2, $3, 'Admin') RETURNING id`
	err = db.QueryRow(query, user.Name, user.Email, string(hashedPassword)).Scan(&user.ID)
	
	if err != nil {
		log.Println("=======================================")
		log.Println("🚨 ERROR DATABASE SAAT REGISTER 🚨")
		log.Println("Pesan Asli:", err.Error())
		log.Println("=======================================")
		
		c.JSON(http.StatusConflict, gin.H{"error": "GAGAL DATABASE: " + err.Error()})
		return
	}

	recordLog("Register Account", user.Email, c.ClientIP())
	c.JSON(http.StatusCreated, gin.H{"status": "success", "message": "Akun berhasil dibuat"})
}

func loginUser(c *gin.Context) {
	var loginData User
	if err := c.ShouldBindJSON(&loginData); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Data tidak valid"})
		return
	}

	var dbUser User
	query := `SELECT id, name, email, password, role FROM users WHERE email = $1`
	err := db.QueryRow(query, loginData.Email).Scan(&dbUser.ID, &dbUser.Name, &dbUser.Email, &dbUser.Password, &dbUser.Role)
	if err != nil {
		log.Println("🚨 ERROR LOGIN (Email tidak ketemu / Tabel belum ada):", err.Error())
		recordLog("Failed Login Attempt", loginData.Email, c.ClientIP())
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Email salah atau error database"})
		return
	}

	err = bcrypt.CompareHashAndPassword([]byte(dbUser.Password), []byte(loginData.Password))
	if err != nil {
		recordLog("Failed Login Attempt", loginData.Email, c.ClientIP())
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Password salah!"})
		return
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"email": dbUser.Email,
		"exp":   time.Now().Add(time.Hour * 24).Unix(),
	})

	tokenString, err := token.SignedString(jwtKey)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Gagal membuat token"})
		return
	}

	recordLog("Successful Login", dbUser.Email, c.ClientIP())
	c.JSON(http.StatusOK, gin.H{"status": "success", "token": tokenString, "name": dbUser.Name})
}

func AuthMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		authHeader := c.GetHeader("Authorization")
		if authHeader == "" {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "Token tidak ditemukan"})
			return
		}
		parts := strings.Split(authHeader, " ")
		if len(parts) != 2 || parts[0] != "Bearer" {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "Format token salah"})
			return
		}
		tokenString := parts[1]
		token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
			return jwtKey, nil
		})
		if err != nil || !token.Valid {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "Token tidak valid"})
			return
		}
		if claims, ok := token.Claims.(jwt.MapClaims); ok && token.Valid {
			c.Set("user_email", claims["email"])
		}
		c.Next()
	}
}

func getAssets(c *gin.Context) {
	rows, err := db.Query("SELECT id, name, category, ip_address, status FROM assets ORDER BY id DESC")
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Gagal query database"})
		return
	}
	defer rows.Close()
	var assets []Asset = []Asset{}
	for rows.Next() {
		var a Asset
		rows.Scan(&a.ID, &a.Name, &a.Category, &a.IPAddress, &a.Status)
		assets = append(assets, a)
	}
	c.JSON(http.StatusOK, gin.H{"status": "success", "data": assets})
}

func createAsset(c *gin.Context) {
	var a Asset
	c.ShouldBindJSON(&a)
	db.QueryRow(`INSERT INTO assets (name, category, ip_address, status) VALUES ($1, $2, $3, $4) RETURNING id`, a.Name, a.Category, a.IPAddress, a.Status).Scan(&a.ID)
	email, _ := c.Get("user_email")
	recordLog("Created Asset: "+a.Name, email.(string), c.ClientIP())
	c.JSON(http.StatusCreated, gin.H{"status": "success", "data": a})
}

func updateAsset(c *gin.Context) {
	id := c.Param("id")
	var a Asset
	c.ShouldBindJSON(&a)
	db.Exec(`UPDATE assets SET name = $1, category = $2, ip_address = $3, status = $4 WHERE id = $5`, a.Name, a.Category, a.IPAddress, a.Status, id)
	email, _ := c.Get("user_email")
	recordLog("Updated Asset ID: "+id, email.(string), c.ClientIP())
	c.JSON(http.StatusOK, gin.H{"status": "success"})
}

func deleteAsset(c *gin.Context) {
	id := c.Param("id")
	db.Exec(`DELETE FROM assets WHERE id = $1`, id)
	email, _ := c.Get("user_email")
	recordLog("Deleted Asset ID: "+id, email.(string), c.ClientIP())
	c.JSON(http.StatusOK, gin.H{"status": "success"})
}

func getLogs(c *gin.Context) {
	rows, err := db.Query("SELECT id, action, user_email, ip_address, timestamp FROM security_logs ORDER BY id DESC LIMIT 50")
	if err != nil {
		c.JSON(http.StatusOK, gin.H{"data": []LogEntry{}})
		return
	}
	defer rows.Close()
	var logs []LogEntry = []LogEntry{}
	for rows.Next() {
		var l LogEntry
		rows.Scan(&l.ID, &l.Action, &l.UserEmail, &l.IPAddress, &l.Timestamp)
		logs = append(logs, l)
	}
	c.JSON(http.StatusOK, gin.H{"data": logs})
}

func getUsers(c *gin.Context) {
	rows, ef := db.Query("SELECT id, name, email, role FROM users ORDER BY id ASC")
	if ef != nil {
		c.JSON(http.StatusOK, gin.H{"data": []User{}})
		return
	}
	defer rows.Close()
	var users []User = []User{}
	for rows.Next() {
		var u User
		rows.Scan(&u.ID, &u.Name, &u.Email, &u.Role)
		users = append(users, u)
	}
	c.JSON(http.StatusOK, gin.H{"data": users})
}

func recordLog(action string, email string, ip string) {
	db.Exec(`INSERT INTO security_logs (action, user_email, ip_address) VALUES ($1, $2, $3)`, action, email, ip)
}

func CORSMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		c.Writer.Header().Set("Access-Control-Allow-Origin", "*")
		c.Writer.Header().Set("Access-Control-Allow-Methods", "POST, GET, OPTIONS, PUT, DELETE")
		c.Writer.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization")
		if c.Request.Method == "OPTIONS" {
			c.AbortWithStatus(204)
			return
		}
		c.Next()
	}
}