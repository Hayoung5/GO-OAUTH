package main

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"path/filepath"

	"github.com/gin-gonic/gin"
	"golang.org/x/oauth2"
	"golang.org/x/oauth2/google"
)

var oauthConf *oauth2.Config

const oauthGoogleUrlAPI = "https://www.googleapis.com/oauth2/v2/userinfo?access_token="

type Config struct {
	Web struct {
		ClientID        string   `json:"client_id"`
		ClientSecret    string   `json:"client_secret"`
		ProjectID       string   `json:"project_id"`
		AuthURI         string   `json:"auth_uri"`
		TokenURI        string   `json:"token_uri"`
		JSOrigins       []string `json:"javascript_origins"`
		RedirectURIs    []string `json:"redirect_uris"`
		ProviderCertURL string   `json:"auth_provider_x509_cert_url"`
	} `json:"web"`
}

func oauthInit() {
	// use a glob pattern to match files named "client*.json"
	fileNames, err := filepath.Glob("client*.json")
	if err != nil {
		log.Fatalf("Failed to find files: %v", err)
	}

	// read the entire file into memory
	data, err := ioutil.ReadFile(fileNames[0])
	if err != nil {
		log.Fatalf("Failed to read file: %v", err)
	}

	// parse the JSON data into a Config struct
	var config Config
	if err := json.Unmarshal(data, &config); err != nil {
		log.Fatalf("Failed to parse JSON: %v", err)
	}

	oauthConf = &oauth2.Config{
		ClientID:     config.Web.ClientID,
		ClientSecret: config.Web.ClientSecret,
		RedirectURL:  config.Web.RedirectURIs[0],
		Scopes: []string{
			"https://www.googleapis.com/auth/userinfo.email",
		},
		Endpoint: google.Endpoint,
	}
}

func getToken() string {
	b := make([]byte, 32)
	rand.Read(b)
	return base64.RawStdEncoding.EncodeToString(b)
}

func getLoginURL(state string) string {
	return oauthConf.AuthCodeURL(state)
}

func main() {
	oauthInit()

	r := gin.Default()

	r.LoadHTMLGlob("templates/*")
	r.GET("/login", func(c *gin.Context) {
		token := getToken()
		url := getLoginURL(token)
		c.HTML(http.StatusOK, "login.html", gin.H{
			"title": "Socal Login",
			"url":   url,
		})
	})
	r.GET("/login/callback", func(c *gin.Context) {
		code := c.Query("code")
		token, err := oauthConf.Exchange(oauth2.NoContext, code)
		if err != nil {
			c.JSON(403, gin.H{"Message": err.Error()})
			return
		}
		response, err := http.Get(oauthGoogleUrlAPI + token.AccessToken)
		if err != nil {
			c.JSON(403, gin.H{"Message": err.Error()})
			return
		}
		defer response.Body.Close()
		contents, err := ioutil.ReadAll(response.Body)
		if err != nil {
			c.JSON(403, gin.H{"Message": err.Error()})
			return
		}
		fmt.Println(string(contents))
		jsonMap := make(map[string]interface{})
		json.Unmarshal(contents, &jsonMap)
		c.JSON(200, jsonMap)
	})
	r.Run()
}
