package main

import (
	"crypto/rand"
	"crypto/sha512"
	"errors"
	"github.com/andlabs/ui"
	"golang.org/x/crypto/nacl/secretbox"
	"golang.org/x/crypto/pbkdf2"
	"io/ioutil"
)

func check(err error) {
	if err != nil {
		panic(err)
	}
}

// getfilename returns the whole filename for the file chosen by the user.
func getfilename(window *ui.Window) string {
	filename := ui.OpenFile(window)
	return filename
}

// encrypt encrypts the given file. If successful, it returns nil else it returns an error.
func encrypt(filename string, pass string) error {
	var salt [16]byte
	var nonce [24]byte
	var secretKey [32]byte

	_, err1 := rand.Read(salt[:]) // reads in a random salt.
	check(err1)

	_, err2 := rand.Read(nonce[:]) // reads in a random nonce.
	check(err2)

	f, err := ioutil.ReadFile(filename)
	if err != nil {
		return errors.New("Error: Unable to read the file.")
	}

	secretbytes := pbkdf2.Key([]byte(pass), salt[:], 3*100000, 32, sha512.New) // generates the key from the password.
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

// decrypt decrypts the given file. If successful, it returns nil else it returns an error.
func decrypt(filename string, pass string) error {

	fb, err := ioutil.ReadFile(filename)
	if err != nil {
		return errors.New("Error: Unable to read the file.")
	}

	var decryptNonce [24]byte
	var salt [16]byte
	var secretKey [32]byte

	copy(salt[:], fb[:16]) // the salt is stored in the 1st 16 bytes of the file.

	iters := int(fb[16]) // the number of iterations (* 100000) needed for the pbkdf2 function.

	secretbytes := pbkdf2.Key([]byte(pass), salt[:], iters*100000, 32, sha512.New)
	copy(secretKey[:], secretbytes[:])

	copy(decryptNonce[:], fb[17:41]) //the nonce is stored after the slt and the number of iterations.
	decrypted, ok := secretbox.Open([]byte{}, fb[41:], &decryptNonce, &secretKey)
	if !ok {
		return errors.New("Error: Unable to decrypt the file. Please check the password you entered and try again.")
	}

	writef := filename[:len(filename)-10] // removes the .encrypted extension.

	err2 := ioutil.WriteFile(writef, decrypted, 0644)
	check(err2)
	return nil
}

// NewWindow genrates the window to be displayed.
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
		if err != nil {
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
