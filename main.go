package main

import (
	"crypto/rand"
	"crypto/sha512"
	"github.com/andlabs/ui"
	"golang.org/x/crypto/nacl/secretbox"
	"golang.org/x/crypto/pbkdf2"
	"io/ioutil"
	"errors"
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

func encrypt(filename string, pass string) error {
	var salt [16]byte
	var nonce [24]byte
	var secretKey [32]byte

	_, err1 := rand.Read(salt[:])
	check(err1)

	_, err2 := rand.Read(nonce[:])
	check(err2)

	f, err := ioutil.ReadFile(filename)
	if err != nil {
		return errors.New("Error: Unable to read the file.")
	}

	secretbytes := pbkdf2.Key([]byte(pass), salt[:], 3*100000, 32, sha512.New)
	copy(secretKey[:], secretbytes[:])

	encrypted := secretbox.Seal(nonce[:], []byte(f), &nonce, &secretKey)
	// 3 is for determining the number of iters needed in the pbkdf2 function. multiply by 100,000 to get the iterations.
	saltiters := append(salt[:], byte(3))
	encrypted = append(saltiters, encrypted...)

	writef := filename + ".encrypted"

	err3 := ioutil.WriteFile(writef, encrypted, 0644)
	check(err3)
	return nil
}

func decrypt(filename string, pass string) error {

	f, err := ioutil.ReadFile(filename)
	if err != nil {
		return errors.New("Error: Unable to read the file.")
	}

	fb := []byte(f)

	var decryptNonce [24]byte
	var salt [16]byte
	var secretKey [32]byte

	copy(salt[:], fb[:16])

	iters := int(fb[16])

	secretbytes := pbkdf2.Key([]byte(pass), salt[:], iters*100000, 32, sha512.New)
	copy(secretKey[:], secretbytes[:])

	copy(decryptNonce[:], fb[17:41])
	decrypted, ok := secretbox.Open([]byte{}, fb[41:], &decryptNonce, &secretKey)
	if !ok {
		return errors.New("Error: Unable to decrypt the file. Please check the password you entered and try again.")
	}

	writef := filename[:len(filename)-10]

	err2 := ioutil.WriteFile(writef, decrypted, 0644)
	check(err2)
	return nil
}

func NewWindow() {
	filelabel := ui.NewLabel("Choose a file to encrypt/decrypt:")
	openbutton := ui.NewButton("Open")

	sep := ui.NewHorizontalSeparator()

	passlabel := ui.NewLabel("Password for encrypting/decrypting:")
	passfield := ui.NewEntry()

	encbutton := ui.NewButton("Encrypt")
	decbutton := ui.NewButton("Decrypt")

	box := ui.NewVerticalBox()
	buttonbox := ui.NewHorizontalBox()

	box.Append(filelabel, false)
	box.Append(openbutton, false)
	box.Append(sep, false)
	box.Append(passlabel, false)
	box.Append(passfield, false)
	buttonbox.Append(encbutton, true)
	buttonbox.Append(decbutton, true)
	box.Append(buttonbox, false)
	buttonbox.SetPadded(true)
	box.SetPadded(true)

	window := ui.NewWindow("Qencrypt", 300, 150, false)
	window.SetChild(box)

	var filename string

	openbutton.OnClicked(func(*ui.Button) {
		filename = getfilename(window)
	})

	encbutton.OnClicked(func(*ui.Button) {
		err := encrypt(filename, passfield.Text())
		if  err != nil {
			ui.MsgBox(window, "Encryption Unsucessful.", err.Error())
		} else {
			message := "The file " + filename + " has been successfully encrypted. Thank you!"
			ui.MsgBox(window, "Encryption Successful!", message)
		}
	})

	decbutton.OnClicked(func(*ui.Button) {
		err := decrypt(filename, passfield.Text())
		if err != nil {
			ui.MsgBox(window, "Decryption Unsuccessful.", err.Error())
		} else {
			message := "The file " + filename + " has been successfully decrypted."
			ui.MsgBox(window, "Decryption Successful!", message)
		}
	})

	window.OnClosing(func(*ui.Window) bool {
		ui.Quit()
		return true
	})
	window.Show()
}

func main() {
	err := ui.Main(func() {
		NewWindow()
	})
	if err != nil {
		panic(err)
	}
}

