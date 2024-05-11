package main

import (
	"bufio"
	"encoding/json"
	"end_to_end_encryption/rsa"
	"end_to_end_encryption/tcp"
	"fmt"
	"math/big"
	"net"
	"os"
	"strings"
)

func main() {
	reader := bufio.NewReader(os.Stdin)
	rsaServise := rsa.New()
	clientPublicKey, clientPrivateKey := rsaServise.GenerateKeys(2048)

	fmt.Println("Подключение к серверу...")
	serverConn, err := net.Dial("tcp", "localhost:8002")
	if err != nil {
		fmt.Println("Ошибка при подключении к серверу:", err)
		return
	}
	fmt.Println("Подключение к серверу успешно.")
	serverTCPServer, _ := tcp.NewTCPHost(serverConn)
	defer serverConn.Close()

	serializedKey, err := json.Marshal(clientPublicKey)
	if err != nil {
		fmt.Println("ошибка сериализации публичного ключа: %v", err)
	}
	fmt.Println("Отправка публичного ключа клиента серверу...")
	err = serverTCPServer.Send(serializedKey)
	if err != nil {
		fmt.Errorf("Ошибка отправки публичного ключа: %v", err)
	}

	fmt.Print("1. Отправлять сообщения\n2. Принимать сообщения\nОтвет: ")
	choice_number, _ := reader.ReadString('\n')
	choice_number = strings.TrimSpace(choice_number)

	if choice_number == "1" {
		fmt.Println("Ожидание публичного ключа получателя...")
		recipientPublicKeyBytes, err := serverTCPServer.Read()
		if err != nil {
			fmt.Println("ошибка чтения публичного ключа получателя: %v", err)
		}
		fmt.Println("Публичный ключ получателя получен.")

		var recipientPublicKey *rsa.PublicKey
		err = json.Unmarshal(recipientPublicKeyBytes, &recipientPublicKey)
		if err != nil {
			fmt.Println("ошибка десериализации публичного ключа получателя: %v", err)
		}
		for {
			send_message(*reader, rsaServise, serverTCPServer, clientPrivateKey, recipientPublicKey)
		}
	} else if choice_number == "2" {
		fmt.Println("Ожидание публичного ключа получателя...")
		senderPublicKeyBytes, err := serverTCPServer.Read()
		if err != nil {
			fmt.Println("ошибка чтения публичного ключа получателя: %v", err)
		}
		fmt.Println("Публичный ключ получателя получен.")

		var sendertPublicKey *rsa.PublicKey
		err = json.Unmarshal(senderPublicKeyBytes, &sendertPublicKey)
		if err != nil {
			fmt.Println("ошибка десериализации публичного ключа получателя: %v", err)
		}
		for {
			read_message(*reader, rsaServise, serverTCPServer, clientPrivateKey, sendertPublicKey)
		}
	}
}

func send_message(reader bufio.Reader, rsaServise *rsa.RSASErvice, server *tcp.TCPHost, clientPrivateKey *rsa.PrivateKey, recipientPublicKey *rsa.PublicKey) {
	fmt.Print("Введите сообщение: ")
	message, _ := reader.ReadString('\n')
	message = strings.TrimSpace(message)
	aesKey, err := rsa.GeneratePrimeNumber(2048)

	if err != nil {
		fmt.Println("Ошибка при создании ключа AES:", err)
	}
	fmt.Println("Ключ AES создан:")
	encryptedMessage, err := rsa.EncryptMessage(message, aesKey)
	msg, err := rsa.DecryptMessage(encryptedMessage, aesKey)
	fmt.Println("расшифрованное сообщение", msg)
	if err != nil {
		fmt.Println("Ошибка при шифровании сообщения:", err)
	}

	signedAesKey := rsaServise.EncryptByPublicKey(aesKey, recipientPublicKey)
	signedAesKeyString := fmt.Sprintf("%x", signedAesKey)
	signed_key_message := signedAesKeyString + encryptedMessage
	hashSignedKeyMessage, err := rsa.HashSHA256(signed_key_message)
	fmt.Println("хеш", hashSignedKeyMessage)
	if err != nil {
		fmt.Println("Ошибка при хешировании сообщения:", err)
		return
	}
	hashSignedKeyMessageBigInt := new(big.Int)
	_, ok := hashSignedKeyMessageBigInt.SetString(hashSignedKeyMessage, 16)
	if !ok {
		fmt.Println("Ошибка при преобразовании hash строки в *big.Int")
		return
	}

	signedHashAesKeyMessage := rsaServise.EncryptByPrivateKey(hashSignedKeyMessageBigInt, clientPrivateKey)

	// Отправка подписанной комбинации серверу
	fmt.Println("Отправка подписанной комбинации серверу...")
	err = server.Send(signedHashAesKeyMessage.Bytes())
	if err != nil {
		fmt.Println("Ошибка при отправке подписанной комбинации:", err)
		return
	}
	fmt.Println("Подписанная комбинация отправлена.")

	// Отправка подписанного ключа серверу
	fmt.Println("Отправка подписанного ключа серверу...")
	err = server.Send(signedAesKey.Bytes())
	if err != nil {
		fmt.Println("Ошибка при отправке подписанного ключа:", err)
		return
	}
	fmt.Println("Подписанный ключ отправлен.")

	// Отправка зашифрованного сообщения серверу
	fmt.Println("Отправка зашифрованного сообщения серверу...")
	err = server.Send([]byte(encryptedMessage))
	if err != nil {
		fmt.Println("Ошибка при отправке зашифрованного сообщения:", err)
		return
	}
	fmt.Println("Зашифрованное сообщение отправлено.")
}

func read_message(reader bufio.Reader, rsaServise *rsa.RSASErvice, server *tcp.TCPHost, clientPrivateKey *rsa.PrivateKey, senderPublicKey *rsa.PublicKey) {
	fmt.Println("Ожидание подписанной комбинации...")
	signedCombBytes, err := server.Read()
	if err != nil {
		fmt.Println("Ошибка чтения подписанной комбинации:", err)
		return
	}
	signedComb := new(big.Int).SetBytes(signedCombBytes)
	fmt.Println("Подписанная комбинации получена.")

	fmt.Println("Ожидание подписанного ключа ...")
	signedAesKeyBytes, err := server.Read()
	if err != nil {
		fmt.Println("Ошибка чтения подписанного ключа:", err)
		return
	}
	signedAesKey := new(big.Int).SetBytes(signedAesKeyBytes)

	fmt.Println("Ожидание зашифрованного сообщения...")
	encryptedMsgBytes, err := server.Read()
	if err != nil {
		fmt.Println("Ошибка чтения зашифрованного сообщения:", err)
		return
	}
	encryptedMsg := string(encryptedMsgBytes)
	fmt.Println("Зашифрованное сообщение получено.")

	signedAesKeyString := fmt.Sprintf("%x", signedAesKey)
	signed_key_message := signedAesKeyString + encryptedMsg
	hashSignedKeyMessage, err := rsa.HashSHA256(signed_key_message)
	if err != nil {
		fmt.Println("Ошибка при хешировании сообщения:", err)
		return
	}
	hashSignedKeyMessageBigInt := new(big.Int)
	_, ok := hashSignedKeyMessageBigInt.SetString(hashSignedKeyMessage, 16)
	if !ok {
		fmt.Println("Ошибка при преобразовании hash строки в *big.Int")
	}

	comb := rsaServise.DecryptByPublicKey(signedComb, senderPublicKey)
	if comb.Cmp(hashSignedKeyMessageBigInt) != 0 {
		fmt.Println("Подпись недействительна")
	} else {
		fmt.Println("Подпись действительна")

	}

	aesKey := rsaServise.DecryptByPrivateKey(signedAesKey, clientPrivateKey)
	msg, err := rsa.DecryptMessage(encryptedMsg, aesKey)
	fmt.Println("Расшифрованное сообщение: ", msg)

}
