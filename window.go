package main

import (
	"crypto/rand"
	"io/ioutil"
	"golang.org/x/crypto/pbkdf2"
	"github.com/andlabs/ui"
	"golang.org/x/crypto/nacl/secretbox"
	"crypto/sha512"
)

func check(err error) {
	if err != nil {
		panic(err)
	}
}

func getfilename(window *ui.Window) string {
	filename := ui.OpenFile(window)
	return filename
}

func encrypt(filename string, pass string) {
	var salt [16]byte
	var nonce [24]byte
	var secretKey [32]byte

	_, err1 := rand.Read(salt[:])
	check(err1)

	_, err2 := rand.Read(nonce[:])
	check(err2)

	f, err := ioutil.ReadFile(filename)
	check(err)

	secretbytes := pbkdf2.Key([]byte(pass), salt[:], 150000, 32, sha512.New)
	copy(secretKey[:], secretbytes[:])

	encrypted := secretbox.Seal(nonce[:], []byte(f), &nonce, &secretKey)
	encrypted = append(salt[:],encrypted...)

	writef := filename + ".encrypted"

	err3 := ioutil.WriteFile(writef, encrypted, 0644)
	check(err3)

}

func decrypt(filename string, pass string) {

	f, err := ioutil.ReadFile(filename)
	check(err)

	fb := []byte(f)

	var decryptNonce [24]byte
	var salt [16]byte
	var secretKey [32]byte

	copy(salt[:], fb[:16])

	secretbytes := pbkdf2.Key([]byte(pass), salt[:], 150000, 32, sha512.New)
	copy(secretKey[:], secretbytes[:])

	copy(decryptNonce[:], fb[16:40])
	decrypted, ok := secretbox.Open([]byte{}, fb[40:], &decryptNonce, &secretKey)
	if !ok {
		panic("decryption error " + filename)
	}

	writef := filename[:len(filename)-10]

	err2 := ioutil.WriteFile(writef, decrypted, 0644)
	check(err2)
}

func setopt(opt bool, optenc *ui.Checkbox, optdec *ui.Checkbox, enc, dec *ui.Button) {
	if opt && optenc.Checked() {
		enc.Enable()
		dec.Disable()
	} else if optdec.Checked() {
		dec.Enable()
		enc.Disable()
	}
}

func main() {
	err := ui.Main(func() {
		filelabel := ui.NewLabel("Choose a file:")
		openbutton := ui.NewButton("Open")

		sep1 := ui.NewHorizontalSeparator()

		optenc := ui.NewCheckbox("Encrypt")
		optdec := ui.NewCheckbox("Decrypt")

		sep2 := ui.NewHorizontalSeparator()

		passlabel := ui.NewLabel("Password:")
		passfield := ui.NewEntry()

		encbutton := ui.NewButton("Encrypt")
		decbutton := ui.NewButton("Decrypt")

		box := ui.NewVerticalBox()

		box.Append(filelabel, false)
		box.Append(openbutton, false)
		box.Append(sep1, false)
		box.Append(optenc, false)
		box.Append(optdec, false)
		box.Append(sep2, false)
		box.Append(passlabel, false)
		box.Append(passfield, false)
		box.Append(encbutton, false)
		box.Append(decbutton, false)

		window := ui.NewWindow("Qencrypt", 300, 150, false)
		window.SetChild(box)

		var filename string

		openbutton.OnClicked(func(*ui.Button) {
			filename = getfilename(window)
		})

		optenc.OnToggled(func(*ui.Checkbox) {
			setopt(true, optenc, optdec, encbutton, decbutton)
		})

		optdec.OnToggled(func(*ui.Checkbox) {
			setopt(false, optenc, optdec, encbutton, decbutton)
		})

		encbutton.OnClicked(func(*ui.Button) {
			encrypt(filename, passfield.Text())
			message := "The file " + filename + " has been successfully encrypted. Thank you!"
			ui.MsgBox(window, "Encryption Successful!", message)
		})

		decbutton.OnClicked(func(*ui.Button) {
			decrypt(filename, passfield.Text())
			message := "The file " + filename + " has been successfully decrypted."
			ui.MsgBox(window, "Decryption Successful!", message)
		})

		window.OnClosing(func(*ui.Window) bool {
			ui.Quit()
			return true
		})
		window.Show()
	})
	if err != nil {
		panic(err)
	}
}
