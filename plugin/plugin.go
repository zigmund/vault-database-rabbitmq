package plugin

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/hashicorp/vault/sdk/database/dbplugin/v5"
	"github.com/hashicorp/vault/sdk/database/helper/dbutil"
	"github.com/hashicorp/vault/sdk/helper/template"
	"github.com/hashicorp/vault/sdk/logical"
	rh "github.com/michaelklishin/rabbit-hole/v3"
	log "github.com/sirupsen/logrus"
	"net/http"
	"strconv"
	"time"
)

type (
	// config contains only string params to parse connection config map
	config struct {
		ConnectionURL      string `json:"connection_url"`
		Username           string `json:"username"`
		Password           string `json:"password"`
		UsernameTemplate   string `json:"username_template"`
		Timeout            string `json:"timeout"`
		InsecureSkipVerify string `json:"insecure_skip_verify"`
	}

	database struct {
		usernameProducer template.StringTemplate
		client           *rh.Client
	}

	statement struct {
		Tags        []string `json:"tags"`
		Permissions []struct {
			Vhost     string `json:"vhost"`
			Read      string `json:"read"`
			Write     string `json:"write"`
			Configure string `json:"configure"`
		} `json:"permissions"`
	}
)

const (
	pluginTypeName          = "rabbitmq"
	defaultUserNameTemplate = `{{ printf "v-%s-%s-%s-%s" (.DisplayName | truncate 15) (.RoleName | truncate 15) (random 20) (unix_time) | replace "." "-" | truncate 100 }}`
)

var (
	// Version - will be set during build
	Version string = "dev"

	// Interface implementation checks
	_ dbplugin.Database       = (*database)(nil)
	_ logical.PluginVersioner = (*database)(nil)
)

// New - returns new dbplugin.Database implementation
// dbplugin.Factory implementation
func New() (interface{}, error) {
	db := &database{}
	return dbplugin.NewDatabaseErrorSanitizerMiddleware(db, db.secretValues), nil
}

// Initialize - initializes RabbitMQ api client with config provided
func (db *database) Initialize(_ context.Context, req dbplugin.InitializeRequest) (dbplugin.InitializeResponse, error) {
	c := &config{
		UsernameTemplate: defaultUserNameTemplate,
		Timeout:          "5s",
	}

	if err := mapToStruct(req.Config, c); err != nil {
		return dbplugin.InitializeResponse{}, fmt.Errorf("error converting connection config to struct: %s", err)
	}

	insecureSkipVerify, err := strconv.ParseBool(c.InsecureSkipVerify)
	if err != nil {
		return dbplugin.InitializeResponse{}, fmt.Errorf("error parsing insecure skip verify: %s", err)
	}

	timeout, err := time.ParseDuration(c.Timeout)
	if err != nil {
		return dbplugin.InitializeResponse{}, fmt.Errorf("error parsing timeout: %s", err)
	}

	switch {
	case len(c.ConnectionURL) == 0:
		return dbplugin.InitializeResponse{}, errors.New("connection_url is required")
	case len(c.Username) == 0:
		return dbplugin.InitializeResponse{}, errors.New("username is required")
	case len(c.Password) == 0:
		return dbplugin.InitializeResponse{}, errors.New("password is required")
	}

	up, err := template.NewTemplate(template.Template(c.UsernameTemplate))
	if err != nil {
		return dbplugin.InitializeResponse{}, fmt.Errorf("unable to initialize username template: %s", err)
	}
	db.usernameProducer = up

	transport := &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: insecureSkipVerify}}
	client, err := rh.NewTLSClient(c.ConnectionURL, c.Username, c.Password, transport)
	if err != nil {
		return dbplugin.InitializeResponse{}, fmt.Errorf("error creating client: %s", err)
	}
	db.client = client
	db.client.SetTimeout(timeout)

	if req.VerifyConnection {
		// Try to list users to check connection
		if _, err = db.client.ListUsers(); err != nil {
			return dbplugin.InitializeResponse{}, fmt.Errorf("error verifying connection: %s", err)
		}
	}

	resp := dbplugin.InitializeResponse{
		Config: req.Config,
	}

	resp.SetSupportedCredentialTypes([]dbplugin.CredentialType{
		dbplugin.CredentialTypePassword,
	})

	return resp, nil
}

// NewUser - creates user in RabbitMQ and updates permissions, according to creation statement
func (db *database) NewUser(_ context.Context, req dbplugin.NewUserRequest) (dbplugin.NewUserResponse, error) {
	username, err := db.generateUsername(req.UsernameConfig)
	if err != nil {
		return dbplugin.NewUserResponse{}, fmt.Errorf("error generating username: %s", err)
	}

	statements := req.Statements.Commands
	if len(statements) == 0 {
		return dbplugin.NewUserResponse{}, fmt.Errorf("error creating user: %s", dbutil.ErrEmptyCreationStatement)
	}

	s := statement{}
	if err = json.Unmarshal([]byte(statements[0]), &s); err != nil {
		return dbplugin.NewUserResponse{}, fmt.Errorf("error unmarshalling creation statement: %s", err)
	}

	if _, err = db.client.PutUser(username, rh.UserSettings{
		Tags:     s.Tags,
		Password: req.Password,
	}); err != nil {
		return dbplugin.NewUserResponse{}, fmt.Errorf("error creating user: %s", err)
	}

	for _, permission := range s.Permissions {
		if _, err = db.client.UpdatePermissionsIn(permission.Vhost, username, rh.Permissions{
			Read:      permission.Read,
			Write:     permission.Write,
			Configure: permission.Configure,
		}); err != nil {
			// Rollback
			if _, delErr := db.client.DeleteUser(username); delErr != nil {
				log.WithError(err).Error("error rolling back user")
			}

			return dbplugin.NewUserResponse{}, fmt.Errorf("error setting user permissions: %s", err)
		}
	}

	log.WithFields(log.Fields{
		"username":    username,
		"tags":        s.Tags,
		"permissions": s.Permissions,
	}).Info("user created")

	return dbplugin.NewUserResponse{
		Username: username,
	}, nil
}

// UpdateUser - updates user in RabbitMQ
func (db *database) UpdateUser(_ context.Context, req dbplugin.UpdateUserRequest) (dbplugin.UpdateUserResponse, error) {
	if req.CredentialType != dbplugin.CredentialTypePassword || req.Password == nil {
		return dbplugin.UpdateUserResponse{}, fmt.Errorf("only supported credential type: %s", dbplugin.CredentialTypePassword.String())
	}

	// Get user for current tags
	user, err := db.client.GetUser(req.Username)
	if err != nil {
		return dbplugin.UpdateUserResponse{}, fmt.Errorf("error getting user: %s", err)
	}

	if _, err = db.client.PutUser(req.Username, rh.UserSettings{
		Tags:     user.Tags,
		Password: req.Password.NewPassword,
	}); err != nil {
		return dbplugin.UpdateUserResponse{}, fmt.Errorf("error updating user: %s", err)
	}

	return dbplugin.UpdateUserResponse{}, nil
}

// DeleteUser - delete user from RabbitMQ
func (db *database) DeleteUser(_ context.Context, req dbplugin.DeleteUserRequest) (dbplugin.DeleteUserResponse, error) {
	if _, err := db.client.DeleteUser(req.Username); err != nil {
		return dbplugin.DeleteUserResponse{}, fmt.Errorf("error deleting user: %s", err)
	}

	log.WithField("username", req.Username).Info("user deleted")

	return dbplugin.DeleteUserResponse{}, nil
}

// Type - returns database plugin type
func (db *database) Type() (string, error) {
	return pluginTypeName, nil
}

// Close - should close connection, but in out care do nothing
func (db *database) Close() error {
	db.client = nil
	return nil
}

// PluginVersion - returns plugin version
// logical.PluginVersioner implementation
func (db *database) PluginVersion() logical.PluginVersion {
	return logical.PluginVersion{Version: Version}
}

// SecretValues - mapping for secrets sanitizer
func (db *database) secretValues() map[string]string {
	return map[string]string{
		db.client.Username: "[username]",
		db.client.Password: "[password]",
	}
}

// generateUsername - generates username with template
func (db *database) generateUsername(metadata dbplugin.UsernameMetadata) (string, error) {
	username, err := db.usernameProducer.Generate(metadata)
	if err != nil {
		return "", fmt.Errorf("error generating username: %s", err)
	}
	return username, nil
}

// mapToStruct - converts map to struct
// works only with strings and integers
func mapToStruct(in map[string]interface{}, out interface{}) error {
	buf := new(bytes.Buffer)
	if err := json.NewEncoder(buf).Encode(in); err != nil {
		return err
	}
	if err := json.NewDecoder(buf).Decode(out); err != nil {
		return err
	}
	return nil
}
