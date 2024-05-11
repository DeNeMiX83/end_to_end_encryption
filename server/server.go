package main

import (
	"encoding/json"
	"end_to_end_encryption/rsa"
	"end_to_end_encryption/tcp"
	"fmt"
	"net"
)

func main() {
	listener, err := net.Listen("tcp", ":8002")
	if err != nil {
		fmt.Println("Ошибка запуска сервера:", err)
	}
	defer listener.Close()

	fmt.Println("сервер запущен. Ожидание подключений...")

	senderConn, err := listener.Accept()
	senderTCP, _ := tcp.NewTCPHost(senderConn)
	if err != nil {
		fmt.Println("Ошибка при принятии подключения:", err)
	}
	fmt.Println("Подключение отправителя...")
	senderPublicKeyBytes, err := senderTCP.Read()
	if err != nil {
		fmt.Println("ошибка чтения публичного ключа: %v", err)
	}
	fmt.Println("Публичный ключ получен.")
	var senderPublicKey *rsa.PublicKey
	err = json.Unmarshal(senderPublicKeyBytes, &senderPublicKey)
	if err != nil {
		fmt.Println("ошибка десериализации публичного ключа: %v", err)
	}

	recipientConn, err := listener.Accept()
	recipientTCP, _ := tcp.NewTCPHost(recipientConn)
	if err != nil {
		fmt.Println("Ошибка при принятии подключения:", err)
	}
	fmt.Println("Подключение получателя...")
	recipientPublicKeyBytes, err := recipientTCP.Read()
	if err != nil {
		fmt.Println("ошибка чтения публичного ключа: %v", err)
	}
	fmt.Println("Публичный ключ получен.")
	var recipientPublicKey *rsa.PublicKey
	err = json.Unmarshal(recipientPublicKeyBytes, &recipientPublicKey)
	if err != nil {
		fmt.Println("ошибка десериализации публичного ключа: %v", err)
	}

	serializedKey, err := json.Marshal(senderPublicKey)
	if err != nil {
		fmt.Println("ошибка сериализации публичного ключа: %v", err)
	}
	fmt.Println("Отправка публичного ключа ...")
	err = recipientTCP.Send(serializedKey)
	if err != nil {
		fmt.Errorf("Ошибка отправки публичного ключа: %v", err)
	}

	serializedKey, err = json.Marshal(recipientPublicKey)
	if err != nil {
		fmt.Println("ошибка сериализации публичного ключа: %v", err)
	}
	fmt.Println("Отправка публичного ключа ...")
	err = senderTCP.Send(serializedKey)
	if err != nil {
		fmt.Errorf("Ошибка отправки публичного ключа: %v", err)
	}

	for {
		fmt.Println("Ожидание подписанной комбинации от отправителя...")
		signedCombBytes, err := senderTCP.Read()
		if err != nil {
			fmt.Println("Ошибка чтения подписанной комбинации:", err)
			return
		}
		fmt.Println("Подписанная комбинации от отправителя получена.")

		fmt.Println("Ожидание подписанного ключа от отправителя...")
		aesKeyBytes, err := senderTCP.Read()
		if err != nil {
			fmt.Println("Ошибка чтения подписанного ключа:", err)
			return
		}
		fmt.Println("Подписанный ключ от отправителя получен.")

		fmt.Println("Ожидание зашифрованного сообщения от отправителя...")
		encryptedMsgBytes, err := senderTCP.Read()
		if err != nil {
			fmt.Println("Ошибка чтения зашифрованного сообщения:", err)
			return
		}
		fmt.Println("Зашифрованное сообщение от отправителя получено.")

		err = recipientTCP.Send(signedCombBytes)
		if err != nil {
			fmt.Println(err)
			return
		}
		err = recipientTCP.Send(aesKeyBytes)
		if err != nil {
			fmt.Println(err)
			return
		}
		err = recipientTCP.Send(encryptedMsgBytes)
		if err != nil {
			fmt.Println(err)
			return
		}
	}

}
