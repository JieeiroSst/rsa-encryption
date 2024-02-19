package main

import (
	"bytes"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net/http"

	"github.com/gin-gonic/gin"
)

func rsaMiddleware(c *gin.Context) {
	encryptedData := c.Request.Header.Get("X-Encrypted-Data")
	privateKeyPem, err := getPrivateKey()
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to load private key"})
		return
	}
	privateKeyBytes := x509.MarshalPKCS1PrivateKey(privateKeyPem)

	block, _ := pem.Decode(privateKeyBytes)
	if block == nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to decode PEM block"})
		return
	}

	privateKey, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to parse private key"})
		return
	}
	ciphertext, err := base64.StdEncoding.DecodeString(encryptedData)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to decode base64 data"})
		return
	}

	decryptedData, err := rsa.DecryptOAEP(sha256.New(), bytes.NewReader(ciphertext), privateKey, nil, nil)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Decryption failed"})
		return
	}
	c.Request.Body = io.NopCloser(bytes.NewReader(decryptedData))
	c.Next()
}

func getPrivateKey() (*rsa.PrivateKey, error) {
	privateKeyPath := "private.pem"
	block, _ := pem.Decode([]byte(privateKeyPath))
	if block == nil {
		return nil, errors.New("failed to decode PEM block")
	}

	privateKey, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		return nil, errors.New("failed to parse private key")
	}

	return privateKey, nil
}

func main() {
	router := gin.New()

	router.Group("/api").Use(rsaMiddleware).POST("/data", func(c *gin.Context) {
		data, err := io.ReadAll(c.Request.Body)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "read data error"})
			return
		}
		fmt.Println("Received data:", string(data))

		c.JSON(http.StatusOK, gin.H{"message": "Data received and processed!"})
	})

	router.Run(":9123")
}
