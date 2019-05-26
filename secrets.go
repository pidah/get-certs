package main

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/awserr"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/secretsmanager"
	"io/ioutil"
	"os"
	"path/filepath"
	"strings"
)

var env = os.Getenv("env")

func main() {

	if env == "" {
		fmt.Println("You must set the `env` environment variable")
		os.Exit(1)
	}

	svc := session.Must(session.NewSession())
	sm := secretsmanager.New(svc, aws.NewConfig().WithRegion("us-west-2"))

	input := &secretsmanager.ListSecretsInput{}
	result, err := sm.ListSecrets(input)
	if err != nil {
		if aerr, ok := err.(awserr.Error); ok {
			switch aerr.Code() {
			case secretsmanager.ErrCodeInvalidParameterException:
				fmt.Println(secretsmanager.ErrCodeInvalidParameterException, aerr.Error())
			case secretsmanager.ErrCodeInvalidNextTokenException:
				fmt.Println(secretsmanager.ErrCodeInvalidNextTokenException, aerr.Error())
			case secretsmanager.ErrCodeInternalServiceError:
				fmt.Println(secretsmanager.ErrCodeInternalServiceError, aerr.Error())
			default:
				fmt.Println(aerr.Error())
			}
		} else {
			fmt.Println(err.Error())
		}
		return
	}

	nginxCertDir := "/etc/nginx/certs/"
	prefix := "ingress/"

	for _, s := range result.SecretList {
		if strings.HasPrefix(*s.Name, prefix+env) {
			output, err := sm.GetSecretValue(&secretsmanager.GetSecretValueInput{SecretId: s.Name})
			if err != nil {
				panic(err.Error())
			}

			var raw map[string]string
			json.Unmarshal([]byte(*output.SecretString), &raw)

			_, err = json.Marshal(raw)
			if err != nil {
				panic(err)
			}

			rawKey, err := base64.StdEncoding.DecodeString(raw["key"])
			if err != nil {
				panic(err)
			}

			rawCert, err := base64.StdEncoding.DecodeString(raw["cert"])
			if err != nil {
				panic(err)
			}

			_, domainName := filepath.Split(*s.Name)
			keyFilename := nginxCertDir + domainName + ".key"
			certFilename := nginxCertDir + domainName + ".crt"

			err = ioutil.WriteFile(keyFilename, rawKey, 0600)
			if err != nil {
				panic(err)
			}
			fmt.Println("Writing", keyFilename)

			err = ioutil.WriteFile(certFilename, rawCert, 0600)
			if err != nil {
				panic(err)
			}
			fmt.Println("Writing", certFilename)
		}
	}
}
