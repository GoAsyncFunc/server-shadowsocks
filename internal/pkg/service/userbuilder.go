package service

import (
	"encoding/base64"
	"fmt"
	"strings"

	api "github.com/GoAsyncFunc/uniproxy/pkg"
	cProtocol "github.com/xtls/xray-core/common/protocol"
	"github.com/xtls/xray-core/common/serial"
	"github.com/xtls/xray-core/proxy/shadowsocks"
	"github.com/xtls/xray-core/proxy/shadowsocks_2022"
)

func buildUser(tag string, userInfo []api.UserInfo, cipher string) (users []*cProtocol.User) {
	users = make([]*cProtocol.User, len(userInfo))

	// Trim cipher to ensure matching works
	cipher = strings.TrimSpace(cipher)

	if strings.Contains(cipher, "2022") {
		newUsers := make([]*cProtocol.User, 0, len(userInfo))

		// Optimization: Calculate invariant key properties outside the loop
		is128 := strings.Contains(cipher, "128")
		targetLen := 32
		if is128 {
			targetLen = 16
		}

		for _, user := range userInfo {
			// Logic: Slice UUID to key length
			uuidStr := user.Uuid
			if len(uuidStr) > targetLen {
				uuidStr = uuidStr[:targetLen]
			}
			userKey := base64.StdEncoding.EncodeToString([]byte(uuidStr))

			account := &shadowsocks_2022.Account{
				Key: userKey,
			}
			newUsers = append(newUsers, &cProtocol.User{
				Level:   0,
				Email:   buildUserEmail(tag, user.Id, user.Uuid),
				Account: serial.ToTypedMessage(account),
			})
		}
		return newUsers
	}

	cipherType := toCipherType(cipher)
	for i, user := range userInfo {
		account := &shadowsocks.Account{
			Password:   user.Uuid,
			CipherType: cipherType,
		}
		users[i] = &cProtocol.User{
			Level:   0,
			Email:   buildUserEmail(tag, user.Id, user.Uuid),
			Account: serial.ToTypedMessage(account),
		}
	}
	return users
}

var cipherTypeMap = map[string]shadowsocks.CipherType{
	"aes-128-gcm":             shadowsocks.CipherType_AES_128_GCM,
	"aes-256-gcm":             shadowsocks.CipherType_AES_256_GCM,
	"chacha20-poly1305":       shadowsocks.CipherType_CHACHA20_POLY1305,
	"chacha20-ietf-poly1305":  shadowsocks.CipherType_CHACHA20_POLY1305,
	"xchacha20-poly1305":      shadowsocks.CipherType_XCHACHA20_POLY1305,
	"xchacha20-ietf-poly1305": shadowsocks.CipherType_XCHACHA20_POLY1305,
	"none":                    shadowsocks.CipherType_NONE,
	"plain":                   shadowsocks.CipherType_NONE,
}

func toCipherType(cipher string) shadowsocks.CipherType {
	if t, ok := cipherTypeMap[strings.ToLower(cipher)]; ok {
		return t
	}
	return shadowsocks.CipherType_UNKNOWN
}

func buildUserEmail(tag string, id int, uuid string) string {
	return fmt.Sprintf("%s|%d|%s", tag, id, uuid)
}
