# RSA Send

## Dependencies:
- numpy>=2.5.4,
- pillow>=12.3.0,
- streamlit>=1.66.0


## Project Setup
### Required
- [git](https://git-scm.com/)
- Python > 3.10
- uv

1. You need to install uv first if not yet:
	- Windows (PowerShell)
	```bash
	powershell -c "iwr [https://astral.sh/uv/install.ps1](https://astral.sh/uv/install.ps1) | iex"
	```
	- Mac/Linux
	```bash
	curl -LsSf [https://astral.sh/uv/install.sh](https://astral.sh/uv/install.sh) | sh
	```
2. Clone this repository
	```
	git clone <URL_REPOSITORY_GITHUB_KELOMPOK>
	cd RSA_send
	```

3. Run uv sync
	```
	uv sync
	```

## Developing Rules
#### KALO BIKIN FITUR BUAT DI BRANCH BARU, PUSH DI MAIN TANPA PULL REQUEST = DI HANTAM

#### KALO BIKIN COMMIT MESSAGE PAKE CONVENTION:
| Tipe | Kegunaan | Contoh Deskripsi |
| :--- | :--- | :--- |
| `feat` | Menambahkan fitur baru ke dalam kode. | `feat(auth): add google login integration` |
| `fix` | Memperbaiki bug atau masalah teknis. | `fix(api): resolve memory leak on user fetch` |
| `docs` | Hanya mengubah dokumen atau berkas *markdown*. | `docs: update setup instructions in README` |
| `style` | Perubahan format kode (spasi, titik koma) tanpa mengubah fungsi. | `style: run prettier formatter on all files` |
| `refactor` | Mengubah kode tanpa menambah fitur ataupun memperbaiki bug. | `refactor: simplify user validation logic` |
| `perf` | Perubahan kode khusus untuk meningkatkan performa. | `perf: optimize database query indexing` |
| `test` | Menambah atau memperbaiki kode pengujian (*unit test*). | `test: add edge case tests for checkout flow` |
| `build` | Perubahan pada sistem build, dependensi, atau skrip eksternal. | `build: upgrade react version to 19` |
| `chore` | Pekerjaan rutin lainnya yang tidak mengubah kode aplikasi. | `chore: release version 1.2.0` |



## TODO:
**Math** 
- [ ] Modul GCD, Buat ngitung GCD, Parameter: a, b, Expected Output: integer hasilGCD, [s, t] dengan s dan t adalah koefisien bezhout 
- [ ] Modul miller_rabin, Buat ngecek Bilangan Prima 
- [ ] Modul generate_primes, Buat generate angka bilangan Prima, Parameter: bits (ukuran bit bilangan prima), Expected Output: integer a (dengan a adalah bilangan prima)
- [ ] Modul mod_inverse, Buat mencari inverse dari a mod b , Parameter: a. b, Expected Output: x (dengan x adalah inversnya), Dependencies: GCD

**Cryptography : Dependencies: Math**
- [ ] Modul generate_key, Parameter: bits (buat di pasing ke module generate primes), Expected Output: [(e, n), (d, n)] dengan d dan e adalah decryptor dan encryptor.
- [ ] Modul encrypt, Paramater: M, e, n (dengan M adalah Plain text, proses chunking per blocknya ngga di sini, modul ini khusus buat ngecrypt apa yang diberikan ke parameternya aja) Expected Output: integer C (dengan C adalah Chiper Text)
- [ ] Modul decrypt, Paramater: C, d, n (dengan C adalah chiper text), Expected Output: int M (dengan M adalah plaintext)

**Pengolahan Citra (Pake Class): Dependencies: numpy, pillow (external libraries)**
- Class ImageProcessor:
	- [ ] Constructor, Parameter: image_path // Simpan Image Path sebagai attribute Object
        Expected Output: Object
            self.image_path = image_path
            self.original_shape = None
            self.total_bytes = 0
            self.raw_bytes = None
            self.chunks = None
		
	- [ ] method .to_bytes, buat ngeconvert gamabr jadi bytes pake numpy, Paramater: , Expected Output: Array[bytes], totalBytes
	- [ ] method .chunk, buat nge chunking bytes nya menjadi block, Paramater: n (n itu dari public key (e, n)), Expected Output: List[chunks] (hasil byte dalam bentuk block dari hasil chunking)
	*PS: Note: Rumus Chunking ((bit_length(n) - 1) // 8) ukuran bit dari n di bagi 8, karena dibagi ke dalam satuan byte*
	- [ ] method .join, Paramater: chunks, nbuat ngegabungin bentuk chunk jadi bentuk bytes lagi, Expected output: Array[bytes]
	- [ ] method .to_image, Paramater: bytes, output_path buat ngebalikin bytes jadi gambar
	
	*PS: Dapat berubah tergantung design atau cara orang yang nulis, tapi kurang lebih methodnya itu.*

// Ribet
**Network : Dependencies: socket, json, struct (python internal libraries)**
- Class NetworkNode:
	- [ ] Constructor, Parameter: host='127.0.0.1', port=5000 // Simpan IP dan Port sebagai attribute Object
		Expected Output: Object
		self.host = host
		self.port = port

	- [ ] method .send_payload, buat ngirim payload data JSON ke node lawan dan nunggu balasan, Parameter: target_host, target_port, payload_dict, Expected Output: dict (respon balik dari penerima)
		PS: Note: Ngirim pake header 4-byte (struct.pack) di depan payload biar JSON ga terpotong saat transmisi soket

	- [ ] method .start_server, buat ngejalanin server soket mendengarkan data masuk, Parameter: handle_callback_func, Expected Output: None (looping listener)

	- [ ] private method ._receive_exact_payload, buat baca byte data secara utuh sesuai panjang di header, Parameter: sock, Expected Output: dict (payload JSON terdecode)

	PS: Masih nentuin bentuk data pas dikirimnya, list/array atau dalamm bentuk string. Mempertimbangkan buat menggunakan list/array biar mempermudah
	
**UI/UX Dependencies: streamlit** 
 
- Fitur Utama:
    - [ ] Image Input Section: Buat Input Image
    - [ ] Connect to Socket : Section buat isi IP / Port Buat Connect dan nembak ke server socket pengirim / penerima
    - [ ] Public Key and Private Key: Tampilin Public key dan private key masing masing client 
    - [ ] Tambahin Toggle buat matiin Enkripsi (PS: Ini fitur juga harus nambahin implementasi di network)
    - [ ] Image Viewer: Buat ngeliat imagenya
            opsional:  Dibikin stream, jadi keliatan setiap byte data yang masuk langsung dirender ke client, tapi ini harus namabahin implementasi dari Pengolahan Citra
    - [ ] Opsional: tambahin fitur buat jalanin flow step by step (Nanti lah kalo dah jadi dulu)

sisanya Se kreatifnya ajah

