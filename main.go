package main

import (
    "crypto/aes"
    "crypto/cipher"
    "crypto/rand"
    "crypto/sha256"
    "fmt"
    "github.com/elgs/gostrgen"
    "github.com/urfave/cli"
    "golang.org/x/crypto/ssh/terminal"
    "io"
    "io/ioutil"
    "os"
)

const SALT_LENGTH = 32

func main() {
    app := cli.NewApp()
    app.Name = "ladon"
    app.Usage = "File encrypt / decrypt tool"
    app.HelpName = "ladon"
    app.UsageText = "ladon [encrypt|decrypt] [input file] [output file]"
    app.Version = "0.0.1"
    app.HideVersion = true
    app.HideHelp = true
    app.Commands = []cli.Command{
        {
            Name:"encrypt",
            Aliases: []string{"e"},
            Usage: "encrypt [input file] [output file]",
            Action:  func(c *cli.Context) error {
                if c.Args().Get(0) == "" || c.Args().Get(1) == "" {
                    return cli.NewExitError("ladon encrypt [input file] [output file]", 1)
                }
                pass,err := inputPass(true)
                if err != nil {
                    return err
                }
                return encrypt(c.Args().Get(0), c.Args().Get(1), pass)
            },
        },
        {
            Name:"decrypt",
            Aliases: []string{"d"},
            Usage: "decrypt [input file] [output file]",
            Action:  func(c *cli.Context) error {
                if c.Args().Get(0) == "" || c.Args().Get(1) == "" {
                    return cli.NewExitError("ladon decrypt [input file] [output file]", 1)
                }
                pass,err := inputPass(false)
                if err != nil {
                    return err
                }
                return decrypt(c.Args().Get(0), c.Args().Get(1), pass)
            },
        },
    }
    app.Run(os.Args)
}

func encrypt(input string, output string, password string) error{
    data, err := ioutil.ReadFile(input)
    if err != nil {
        return err
    }

    salt, err := gostrgen.RandGen(SALT_LENGTH, gostrgen.Lower | gostrgen.Digit, "", "")
    saltbyte := []byte(salt)
    if err != nil {
        return err
    }
    password += salt
    key := sha256.Sum256([]byte(password))
    block, err := aes.NewCipher(key[:])
    if err != nil {
        return err
    }

    cipherData := make([]byte, aes.BlockSize+len(data))
    iv := cipherData[:aes.BlockSize]
    if _, err := io.ReadFull(rand.Reader, iv); err != nil {
        return err
    }
    stream := cipher.NewOFB(block, iv)
    stream.XORKeyStream(cipherData[aes.BlockSize:], data)
    return ioutil.WriteFile(output, append(saltbyte,cipherData...), 0600)
}

func decrypt(input string, output string, password string) error{
    data, err := ioutil.ReadFile(input)
    if err != nil {
        return err
    }

    saltbyte := data[:SALT_LENGTH]
    data = data[SALT_LENGTH:]
    salt := string(saltbyte)
    password += salt
    key := sha256.Sum256([]byte(password))
    block, err := aes.NewCipher(key[:])
    if err != nil {
        return err
    }

    decryptedData := make([]byte, len(data)-aes.BlockSize)
    iv := data[:aes.BlockSize]
    stream := cipher.NewOFB(block, iv)
    stream.XORKeyStream(decryptedData, data[aes.BlockSize:])
    return ioutil.WriteFile(output, decryptedData, 0644)
}

func inputPass(try bool) (string,error) {
    fmt.Print("Input password: ")
    password1, err1 := terminal.ReadPassword(0)
    fmt.Println("")
    if err1 != nil {
        return "",cli.NewExitError("read error", 1)
    }
    if !try {
        return string(password1),nil
    }
    fmt.Print("Input password again: ")
    password2, err2 := terminal.ReadPassword(0)
    fmt.Println("")
    if err2 != nil {
        return "",cli.NewExitError("read error", 1)
    }
    if string(password1) != string(password2) {
        return "",cli.NewExitError("Password is different", 1)
    }
    fmt.Println("")
    return string(password1),nil
}
