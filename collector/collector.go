package main

import (
	"blind_digital_signature/rsa"
	"blind_digital_signature/tcp"
	"encoding/json"
	"fmt"
	"math/big"
	"net"
)

func main() {
	rsaServise := rsa.New()

	listener, err := net.Listen("tcp", ":8003")
	if err != nil {
		fmt.Println("Ошибка запуска коллектора:", err)
	}
	defer listener.Close()

	fmt.Println("Коллектор запущен. Ожидание подключений...")
	msgs_count := make(map[string]int)
	for {
		clientConn, err := listener.Accept()
		clientTCP, _ := tcp.NewTCPHost(clientConn)
		if err != nil {
			fmt.Println("Ошибка при принятии подключения:", err)
			continue
		}

		go func(clientTCP *tcp.TCPHost) {
			defer clientTCP.Close()

			for {

				fmt.Println("Ожидание публичного ключа регистратора...")
				registerPublickKeyBytes, err := clientTCP.Read()
				if err != nil {
					fmt.Println("ошибка чтения публичного ключа регистратора: %v", err)
				}
				fmt.Println("Публичный ключ регистратора получен.")
				var registerPublickKey *rsa.PublicKey
				err = json.Unmarshal(registerPublickKeyBytes, &registerPublickKey)
				if err != nil {
					fmt.Println("ошибка десериализации публичного ключа регистратора: %v", err)
				}

				fmt.Println("Ожидание сообщения...")
				msgBytes, err := clientTCP.Read()
				if err != nil {
					fmt.Println("ошибка чтения сообщения: %v", err)
				}
				fmt.Println("Сообщение получено.")
				msg := string(msgBytes)

				fmt.Println("Ожидание подписанного сообщения...")
				signedMsgBytes, err := clientTCP.Read()
				if err != nil {
					fmt.Println("ошибка чтения сообщения: %v", err)
				}
				fmt.Println("подписанное сообщение получено.")
				signedMsg := new(big.Int).SetBytes(signedMsgBytes)

				hashMessage, err := rsa.HashSHA256(msg)
				if err != nil {
					fmt.Println("Ошибка при хешировании сообщения:", err)
				}
				hashMessageBigInt := new(big.Int)
				_, ok := hashMessageBigInt.SetString(hashMessage, 16)
				if !ok {
					fmt.Println("Ошибка при преобразовании hash строки в *big.Int")
				}
				decrtyptSignedMsg := rsaServise.DecryptByPublicKey(signedMsg, registerPublickKey)
				if decrtyptSignedMsg.Cmp(hashMessageBigInt) != 0 {
					fmt.Println("Подпись недействительна")
					return
				}

				msgs_count[msg]++
				fmt.Println("Подписи", msgs_count)
			}
		}(clientTCP)

	}
}
