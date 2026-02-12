package ssh

import (
	"golang.org/x/crypto/ssh"
)

func BuildAuthMethod(username, password string) []ssh.AuthMethod {
	var authMethods []ssh.AuthMethod

	if username != "" && password != "" {
		authMethods = append(authMethods, ssh.Password(password))
	}

	return authMethods
}
