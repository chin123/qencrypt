package main

import (
	"crypto/rand"
	"io/ioutil"

	"github.com/andlabs/ui"
	"golang.org/x/crypto/nacl/secretbox"
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

func encrypt(filename string) {
	var secretKey [32]byte
	_, err1 := rand.Read(secretKey[:])
	check(err1)

	var nonce [24]byte

	_, err2 := rand.Read(nonce[:])
	check(err2)

	f, err := ioutil.ReadFile(filename)
	check(err)

	encrypted := secretbox.Seal(nonce[:], []byte(f), &nonce, &secretKey)

	writef := filename + ".encrypted"

	err3 := ioutil.WriteFile(writef, encrypted, 0644)
	check(err3)

	passfile := filename + "-password.txt"

	keyforfile := string(secretKey[:])

	err3 = ioutil.WriteFile(passfile, []byte(keyforfile), 0644)
	check(err3)
}

func decrypt(filename string, passname string) {

	f, err := ioutil.ReadFile(filename)
	check(err)

	fb := []byte(f)

	var decryptNonce [24]byte
	var secretKey [32]byte

	pass, err := ioutil.ReadFile(passname)
	check(err)

	copy(secretKey[:], pass)
	copy(decryptNonce[:], fb[:24])
	decrypted, ok := secretbox.Open([]byte{}, fb[24:], &decryptNonce, &secretKey)
	if !ok {
		panic("decryption error " + filename)
	}

	writef := filename[:len(filename)-10]

	err2 := ioutil.WriteFile(writef, decrypted, 0644)
	check(err2)
}

func setopt(opt bool, optenc *ui.Checkbox, optdec *ui.Checkbox, enc, dec, pass *ui.Button) {
	if opt && optenc.Checked() {
		enc.Enable()
		dec.Disable()
		pass.Disable()
	} else if optdec.Checked() {
		dec.Enable()
		enc.Disable()
		pass.Enable()
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

		encbutton := ui.NewButton("Encrypt")

		passbutton := ui.NewButton("Open Password File")

		decbutton := ui.NewButton("Decrypt")

		box := ui.NewVerticalBox()

		box.Append(filelabel, false)
		box.Append(openbutton, false)
		box.Append(sep1, false)
		box.Append(optenc, false)
		box.Append(optdec, false)
		box.Append(sep2, false)
		box.Append(encbutton, false)
		box.Append(passbutton, false)
		box.Append(decbutton, false)

		window := ui.NewWindow("Qencrypt", 300, 150, false)
		window.SetChild(box)

		var filename, passname string

		openbutton.OnClicked(func(*ui.Button) {
			filename = getfilename(window)
		})

		passbutton.OnClicked(func(*ui.Button) {
			passname = getfilename(window)
		})

		optenc.OnToggled(func(*ui.Checkbox) {
			setopt(true, optenc, optdec, encbutton, decbutton, passbutton)
		})

		optdec.OnToggled(func(*ui.Checkbox) {
			setopt(false, optenc, optdec, encbutton, decbutton, passbutton)
		})

		encbutton.OnClicked(func(*ui.Button) {
			encrypt(filename)
			message := "The file " + filename + " has been successfully encrypted. The password file which is required for decryption is also placed in the same folder. Please keep it safely as it is required to decrypt the file. Thank you!"
			ui.MsgBox(window, "Encryption Successful!", message)
		})

		decbutton.OnClicked(func(*ui.Button) {
			decrypt(filename, passname)
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
