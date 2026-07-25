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

// --- STRUKTUR DATA ---
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

// Rahasia JWT (Jangan simpan hardcode di production aslinya!)
var jwtKey = []byte("assetflow_super_secret_key_2026")
var db *sql.DB

func main() {
	// 1. KONEKSI DATABASE
	// UNTUK TESTING SEMENTARA, boleh ditaruh langsung di sini.
	// HAPUS SEBELUM UPLOAD KE GITHUB!
	connStr := os.Getenv("DATABASE_URL")
	if connStr == "" {
		log.Fatal("ERROR: DATABASE_URL tidak diset.")
	}

	var err error
	db, err = sql.Open("postgres", connStr)
	if err != nil {
		log.Fatal("Gagal membuka koneksi database: ", err)
	}
	defer db.Close()

	// 2. SETUP GIN ROUTER
	r := gin.Default()
	r.Use(CORSMiddleware())

	api := r.Group("/api/v1")
	{
		// Rute Terbuka (Public)
		api.POST("/register", registerUser)
		api.POST("/login", loginUser)

		// Rute Terlindungi (Membutuhkan Login / Token JWT)
		protected := api.Group("/")
		protected.Use(AuthMiddleware()) // Pasang satpam di rute ini
		{
			// CRUD Assets
			protected.GET("/assets", getAssets)
			protected.POST("/assets", createAsset)
			protected.PUT("/assets/:id", updateAsset)
			protected.DELETE("/assets/:id", deleteAsset)

			// Data tambahan untuk Dashboard
			protected.GET("/logs", getLogs)
			protected.GET("/users", getUsers)
		}
	}

	log.Println("🚀 Enterprise Backend berjalan di http://localhost:8080")
	r.Run(":8080")
}

// ==========================================
// 🔐 AUTHENTICATION HANDLERS
// ==========================================

func registerUser(c *gin.Context) {
	var user User
	if err := c.ShouldBindJSON(&user); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Data tidak valid"})
		return
	}

	// Hash password sebelum disimpan ke database (Keamanan tingkat tinggi)
	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(user.Password), bcrypt.DefaultCost)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Gagal enkripsi password"})
		return
	}

	query := `INSERT INTO users (name, email, password, role) VALUES ($1, $2, $3, 'Admin') RETURNING id`
	err = db.QueryRow(query, user.Name, user.Email, string(hashedPassword)).Scan(&user.ID)
	
	if err != nil {
		// Biasanya error karena email sudah terdaftar (UNIQUE constraint)
		c.JSON(http.StatusConflict, gin.H{"error": "Email sudah terdaftar atau terjadi kesalahan database"})
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

	// Cari user di database berdasarkan email
	var dbUser User
	query := `SELECT id, name, email, password, role FROM users WHERE email = $1`
	err := db.QueryRow(query, loginData.Email).Scan(&dbUser.ID, &dbUser.Name, &dbUser.Email, &dbUser.Password, &dbUser.Role)
	if err != nil {
		recordLog("Failed Login Attempt", loginData.Email, c.ClientIP())
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Email atau password salah"})
		return
	}

	// Cocokkan password yang diinput dengan Hash di database
	err = bcrypt.CompareHashAndPassword([]byte(dbUser.Password), []byte(loginData.Password))
	if err != nil {
		recordLog("Failed Login Attempt", loginData.Email, c.ClientIP())
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Email atau password salah"})
		return
	}

	// Pembuatan Token JWT (Berlaku 24 Jam)
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
	c.JSON(http.StatusOK, gin.H{
		"status": "success",
		"token":  tokenString,
		"name":   dbUser.Name,
	})
}

// AuthMiddleware - Fungsi Satpam yang mengecek token JWT
func AuthMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		authHeader := c.GetHeader("Authorization")
		if authHeader == "" {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "Token tidak ditemukan"})
			return
		}

		// Header format: "Bearer <token>"
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
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "Token tidak valid atau kadaluarsa"})
			return
		}

		// Simpan email user ke context agar bisa dipakai oleh fungsi lain
		if claims, ok := token.Claims.(jwt.MapClaims); ok && token.Valid {
			c.Set("user_email", claims["email"])
		}

		c.Next()
	}
}

// ==========================================
// 🏢 CRUD ASSETS & DASHBOARD DATA HANDLERS
// ==========================================

func getAssets(c *gin.Context) {
	rows, err := db.Query("SELECT id, name, category, ip_address, status FROM assets ORDER BY id DESC")
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Gagal query ke database"})
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

// Handlers untuk menu tambahan di sidebar
func getLogs(c *gin.Context) {
	rows, err := db.Query("SELECT id, action, user_email, ip_address, timestamp FROM security_logs ORDER BY id DESC LIMIT 50")
	if err != nil {
		c.JSON(http.StatusOK, gin.H{"data": []LogEntry{}}) // Return kosong jika tabel belum ada
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
	rows, err := db.Query("SELECT id, name, email, role FROM users ORDER BY id ASC")
	if err != nil {
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

// Helper untuk mencatat log ke database
func recordLog(action string, email string, ip string) {
	db.Exec(`INSERT INTO security_logs (action, user_email, ip_address) VALUES ($1, $2, $3)`, action, email, ip)
}

// CORS Middleware
func CORSMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		c.Writer.Header().Set("Access-Control-Allow-Origin", "*")
		c.Writer.Header().Set("Access-Control-Allow-Methods", "POST, GET, OPTIONS, PUT, DELETE")
		c.Writer.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization") // Tambah Authorization

		if c.Request.Method == "OPTIONS" {
			c.AbortWithStatus(204)
			return
		}
		c.Next()
	}
}