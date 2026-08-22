package main

import "fmt"

// 1. Membuat cetakan data (Struct)
// Biasakan menggunakan awalan huruf kapital untuk properti struct jika ingin diakses dari luar
type User struct {
	Name  string
	Email string
}

// ==========================================
// CONTOH 1: TANPA BINTANG (Hanya Di-Copy / Value)
// ==========================================
// Karena tidak ada tanda (*), fungsi ini hanya menerima "FOTOKOPI" dari data user.
// Hasilnya: Perubahan di sini TIDAK AKAN ngefek ke data aslinya!
func (u User) GantiNama(namaBaru string) {
	u.Name = namaBaru 
	
	// KITA BUKTIKAN DI SINI:
	fmt.Println("   -> [DI DALAM FUNGSI GantiNama]: Nama fotokopi berhasil diubah menjadi:", u.Name)
}

// ==========================================
// CONTOH 2: DENGAN BINTANG (Ubah Asli / Pointer)
// ==========================================
// Tanda (u *User) artinya fungsi ini masuk langsung ke alamat memori data aslinya.
func (u *User) UpdateEmail(newEmail string) {
	u.Email = newEmail 
}

func main() {
	// Membuat "objek" awal
	pengguna := User{
		Name:  "Muhammad Sultan Ihsan",
		Email: "email_lama@gmail.com",
	}

	fmt.Println("1. Data AWAL:", pengguna)

	// Mari kita tes fungsi TANPA bintang (Copy)
	pengguna.GantiNama("Hacker 123")
	fmt.Println("2. Setelah GantiNama (Namanya TETAP, karena cuma fotokopi yang diubah):", pengguna)

	// Mari kita tes fungsi DENGAN bintang (Pointer)
	pengguna.UpdateEmail("ikgsanikhsan93@gmail.com")
	fmt.Println("3. Setelah UpdateEmail (Emailnya BERUBAH permanen!):", pengguna)
}