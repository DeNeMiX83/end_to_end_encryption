package rsa

import (
	"bytes"
	"errors"
	"fmt"
	"math/big"
	"os"
	"os/exec"
	"strings"
)

type PublicKey struct {
	E *big.Int
	N *big.Int
}

type PrivateKey struct {
	D *big.Int
	N *big.Int
}

type RSASErvice struct {
}

func New() *RSASErvice {
	return &RSASErvice{}
}

func (s *RSASErvice) GenerateKeys(bits int) (*PublicKey, *PrivateKey) {
	p, err := GeneratePrimeNumber(bits)
	if err != nil {
		fmt.Println("Error: ", err)
	}
	q, err := GeneratePrimeNumber(bits)
	if err != nil {
		fmt.Println("Error: ", err)
	}

	n := new(big.Int).Mul(p, q)

	phi := new(big.Int).Mul(new(big.Int).Sub(p, big.NewInt(1)), new(big.Int).Sub(q, big.NewInt(1)))

	e := new(big.Int).Sub(phi, big.NewInt(1))
	for e.Cmp(phi) < 0 {
		if GCD(e, phi).Cmp(big.NewInt(1)) == 0 {
			break
		}
		e = new(big.Int).Sub(e, big.NewInt(1))
	}

	d, _ := CalculateInverseNumber(e, phi)
	return &PublicKey{e, n}, &PrivateKey{d, n}
}

func (s *RSASErvice) EncryptByPublicKey(message *big.Int, publicKey *PublicKey) *big.Int {
	cipherText := new(big.Int).Exp(message, publicKey.E, publicKey.N)
	return cipherText
}

func (s *RSASErvice) EncryptByPrivateKey(message *big.Int, privateKey *PrivateKey) *big.Int {
	cipherText := new(big.Int).Exp(message, privateKey.D, privateKey.N)
	return cipherText
}

func (s *RSASErvice) DecryptByPublicKey(message *big.Int, publicKey *PublicKey) *big.Int {
	plainText := new(big.Int).Exp(message, publicKey.E, publicKey.N)
	return plainText
}

func (s *RSASErvice) DecryptByPrivateKey(message *big.Int, privateKey *PrivateKey) *big.Int {
	plainText := new(big.Int).Exp(message, privateKey.D, privateKey.N)
	return plainText
}

func GCD(a, b *big.Int) *big.Int {
	zero := big.NewInt(0)
	for b.Cmp(zero) != 0 {
		a, b = b, new(big.Int).Mod(a, b)
	}
	return a
}

func ExtendedGCD(a, b *big.Int) (*big.Int, *big.Int, *big.Int) {
	zero := big.NewInt(0)
	one := big.NewInt(1)
	if b.Cmp(zero) == 0 {
		return a, one, zero
	}

	gcd, x, y := ExtendedGCD(b, new(big.Int).Mod(a, b))
	xTemp := new(big.Int).Set(x)
	yTemp := new(big.Int).Set(y)
	x = yTemp
	y = new(big.Int).Sub(xTemp, new(big.Int).Mul(new(big.Int).Div(a, b), yTemp))
	return gcd, x, y
}

func CalculateInverseNumber(value, n *big.Int) (*big.Int, error) {
	gcd, x, _ := ExtendedGCD(value, n)
	if gcd.Cmp(big.NewInt(1)) != 0 {
		return nil, errors.New("inverse does not exist")
	}

	return x.Mod(x, n), nil
}

func GeneratePrimeNumber(bits int) (*big.Int, error) {
	cmd := exec.Command("openssl", "prime", "-generate", "-bits", fmt.Sprint(bits), "-hex")

	output, err := cmd.Output()
	if err != nil {
		fmt.Println("Ошибка при выполнении команды:", err)
		return nil, err
	}

	primeHex := strings.TrimSpace(string(output))

	prime := new(big.Int)
	_, ok := prime.SetString(primeHex, 16)
	if !ok {
		fmt.Println("Ошибка при преобразовании шестнадцатеричной строки в *big.Int:", err)
		return nil, fmt.Errorf("не удалось преобразовать шестнадцатеричную строку в *big.Int")
	}

	return prime, nil
}

func HashSHA256(val string) (string, error) {
	cmd := exec.Command("openssl", "dgst", "-sha256", "-hex")
	cmd.Stdin = bytes.NewBufferString(val)

	output, err := cmd.Output()
	if err != nil {
		return "", fmt.Errorf("failed to hash val: %s, stderr: %s", output, err)
	}

	output_str := strings.TrimSpace(string(output))
	parts := strings.Split(output_str, " ")

	return parts[1], nil
}

func GenerateRandomNumber(bite int) (*big.Int, error) {
	cmd := exec.Command("openssl", "rand", "-hex", fmt.Sprint(bite))

	output, err := cmd.Output()
	if err != nil {
		fmt.Println("Ошибка при генерации случайного числа:", err)
		return nil, err
	}

	randomNumberHex := strings.TrimSpace(string(output))

	randomNumber := new(big.Int)
	_, ok := randomNumber.SetString(randomNumberHex, 16)
	if !ok {
		return nil, fmt.Errorf("не удалось преобразовать шестнадцатеричную строку в *big.Int")
	}

	return randomNumber, nil
}

func EncryptMessage(plainText string, key *big.Int) (string, error) {
	tmpFile, err := os.CreateTemp("", "toEncrypt")
	if err != nil {
		return "", fmt.Errorf("не удалось создать временный файл: %v", err)
	}
	defer os.Remove(tmpFile.Name())

	if _, err := tmpFile.Write([]byte(plainText)); err != nil {
		return "", fmt.Errorf("не удалось записать во временный файл: %v", err)
	}
	if err := tmpFile.Close(); err != nil {
		return "", fmt.Errorf("не удалось закрыть временный файл: %v", err)
	}

	tmpKeyFile, err := os.CreateTemp("", "key")
	if err != nil {
		return "", fmt.Errorf("не удалось создать временный файл: %v", err)
	}
	defer os.Remove(tmpKeyFile.Name())

	if _, err := tmpKeyFile.Write(key.Bytes()); err != nil {
		return "", fmt.Errorf("не удалось записать во временный файл: %v", err)
	}
	if err := tmpKeyFile.Close(); err != nil {
		return "", fmt.Errorf("не удалось закрыть временный файл: %v", err)
	}

	tmpEncryptedFile, err := os.CreateTemp("", "encrypted")
	if err != nil {
		return "", fmt.Errorf("не удалось создать временный файл для шифрования: %v", err)
	}
	defer os.Remove(tmpEncryptedFile.Name())

	cmd := exec.Command(
		"openssl", "enc", "-aes-256-ofb",
		"-in", tmpFile.Name(),
		"-out", tmpEncryptedFile.Name(),
		"-pass", "file:"+tmpKeyFile.Name(),
		"-pbkdf2", "-iter", "10000",
	)
	if err := cmd.Run(); err != nil {
		return "", fmt.Errorf("ошибка при выполнении шифрования: %v", err)
	}

	cipherText, err := os.ReadFile((tmpEncryptedFile.Name()))
	if err != nil {
		return "", err
	}

	return string(cipherText), nil
}

func DecryptMessage(cipherText string, key *big.Int) (string, error) {

	tmpEncryptedFile, err := os.CreateTemp("", "toDecrypt")
	if err != nil {
		return "", fmt.Errorf("не удалось создать временный файл: %v", err)
	}
	defer os.Remove(tmpEncryptedFile.Name())

	if _, err := tmpEncryptedFile.Write([]byte(cipherText)); err != nil {
		return "", fmt.Errorf("не удалось записать во временный файл: %v", err)
	}
	if err := tmpEncryptedFile.Close(); err != nil {
		return "", fmt.Errorf("не удалось закрыть временный файл: %v", err)
	}

	tmpKeyFile, err := os.CreateTemp("", "key")
	if err != nil {
		return "", fmt.Errorf("не удалось создать временный файл: %v", err)
	}
	defer os.Remove(tmpKeyFile.Name())

	if _, err := tmpKeyFile.Write(key.Bytes()); err != nil {
		return "", fmt.Errorf("не удалось записать во временный файл: %v", err)
	}
	if err := tmpKeyFile.Close(); err != nil {
		return "", fmt.Errorf("не удалось закрыть временный файл: %v", err)
	}

	tmpDecryptedFile, err := os.CreateTemp("", "decrypted")
	if err != nil {
		return "", fmt.Errorf("не удалось создать временный файл для дешифрования: %v", err)
	}
	defer os.Remove(tmpEncryptedFile.Name())

	cmd := exec.Command(
		"openssl", "enc", "-d", "-aes-256-ofb",
		"-in", tmpEncryptedFile.Name(),
		"-out", tmpDecryptedFile.Name(),
		"-pass", "file:"+tmpKeyFile.Name(),
		"-pbkdf2", "-iter", "10000",
	)
	if err := cmd.Run(); err != nil {
		return "", fmt.Errorf("ошибка при выполнении разшифрования: %v", err)
	}

	plainText, err := os.ReadFile((tmpDecryptedFile.Name()))
	if err != nil {
		return "", err
	}

	return string(plainText), nil
}
