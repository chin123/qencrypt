package main

import (
	"crypto/rand"
	"errors"
	"github.com/andlabs/ui"
	"io"
	"io/ioutil"
	"crypto/aes"
	"crypto/cipher"
	"encoding/base64"
)

import _ "github.com/andlabs/ui/winmanifest"

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
	var key [32]byte
	var salt [16]byte

	_, err := rand.Read(salt[:]) // reads in a random salt.
	check(err)

	f, err := ioutil.ReadFile(filename)
	if err != nil {
		return errors.New("Error: Unable to read the file.")
	}

	secretbytes := pbkdf2.Key([]byte(pass), salt[:], 3*100000, 32, sha512.New) // generates the key from the password.
	copy(key[:], secretbytes[:])

	block, err := aes.NewCipher(key)
	check(err)

	// The IV needs to be unique, but not secure. Therefore it's common to
	// include it at the beginning of the ciphertext.
	ciphertext := make([]byte, aes.BlockSize+len([]byte(f)))
	iv := ciphertext[:aes.BlockSize]
	if _, err := io.ReadFull(rand.Reader, iv); err != nil {
		panic(err)
	}

	stream := cipher.NewCFBEncrypter(block, iv)
	stream.XORKeyStream(ciphertext[aes.BlockSize:], []byte(f))

	writef := filename + ".encrypted"
	ciphertext = append(byte(3), ciphertext...)
	ciphertext = append(salt[:], ciphertext...)

	err3 := ioutil.WriteFile(writef, []byte(base64.URLEncoding.EncodeToString(ciphertext)) , 0644)
	check(err3)
	return nil
}

// decrypt decrypts the given file. If successful, it returns nil else it returns an error.
func decrypt(filename string, pass string) error {

	fb, err := ioutil.ReadFile(filename)
	if err != nil {
		return errors.New("Error: Unable to read the file.")
	}

	var key [32]byte
	var salt [16]byte

	copy(salt[:], fb[:16]) // the salt is stored in the 1st 16 bytes of the file.

	iters := int(fb[16]) // the number of iterations (* 100000) needed for the pbkdf2 function.


	secretbytes := pbkdf2.Key([]byte(pass), salt[:], iters*100000, 32, sha512.New)
	copy(key[:], secretbytes[:])

	ciphertext, _ := base64.URLEncoding.DecodeString(string(fb[17:]))

	block, err := aes.NewCipher(key)
	if err != nil {
		panic(err)
	}

	// The IV needs to be unique, but not secure. Therefore it's common to
	// include it at the beginning of the ciphertext.
	if len(ciphertext) < aes.BlockSize {
		panic("ciphertext too short")
	}
	iv := ciphertext[:aes.BlockSize]
	ciphertext = ciphertext[aes.BlockSize:]

	stream := cipher.NewCFBDecrypter(block, iv)

	// XORKeyStream can work in-place if the two arguments are the same.
	stream.XORKeyStream(ciphertext, ciphertext)


	writef := filename[:len(filename)-10] // removes the .encrypted extension.

	err2 := ioutil.WriteFile(writef, []byte(ciphertext), 0644)
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
