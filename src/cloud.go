package apm

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"runtime"
	"time"

	"strings"

	"github.com/dropbox/dropbox-sdk-go-unofficial/v6/dropbox"
	"github.com/dropbox/dropbox-sdk-go-unofficial/v6/dropbox/files"
	"github.com/google/go-github/v60/github"
	"golang.org/x/oauth2"
	"golang.org/x/oauth2/google"
	"google.golang.org/api/drive/v3"
	"google.golang.org/api/option"
)

const DriveFolderID = "100G-gs-wQnjmGipXdKFBBNd-Qbu6PpYJ"

type CloudProvider interface {
	UploadVault(vaultPath string, customKey string) (string, error)
	DownloadVault(fileID string) ([]byte, error)
	SyncVault(vaultPath, fileID string) error
	DeleteVault(fileID string) error
	ResolveKeyToID(key string) (string, error)
}

func GenerateRetrievalKey() (string, error) {
	return GenerateRandomWords()
}

type GoogleDriveManager struct {
	Service *drive.Service
	Mode    string
}

// NewGoogleDriveManager expects a ready OAuth token because CI and CLI flows
// handle the browser ceremony separately and persist the resulting token blob.
func NewGoogleDriveManager(ctx context.Context, credsJSON []byte, tokenJSON []byte, mode string) (*GoogleDriveManager, error) {
	if len(credsJSON) == 0 {
		return nil, fmt.Errorf("cloud credentials missing")
	}

	config, err := google.ConfigFromJSON(credsJSON, drive.DriveFileScope)
	if err != nil {
		return nil, fmt.Errorf("unable to parse config: %v", err)
	}

	var client *http.Client
	if len(tokenJSON) > 0 {
		tok := &oauth2.Token{}
		if err := json.Unmarshal(tokenJSON, tok); err != nil {
			return nil, fmt.Errorf("unable to parse token: %v", err)
		}
		client = config.Client(ctx, tok)
	} else {
		return nil, fmt.Errorf("cloud token missing")
	}

	srv, err := drive.NewService(ctx, option.WithHTTPClient(client))
	if err != nil {
		return nil, fmt.Errorf("unable to retrieve Drive client: %v", err)
	}

	return &GoogleDriveManager{Service: srv, Mode: mode}, nil
}

// UploadVault stores the encrypted vault under a non-descriptive name and, in
// public mode, exposes only the file object while relying on the retrieval key
// hash as the lookup mechanism.
func (cm *GoogleDriveManager) UploadVault(vaultPath string, customKey string) (string, error) {
	f, err := os.Open(vaultPath)
	if err != nil {
		return "", fmt.Errorf("unable to open vault file: %v", err)
	}
	defer f.Close()

	randomName, err := GenerateRandomHex(6)
	if err != nil {
		randomName = fmt.Sprintf("vault_%d", time.Now().Unix())
	} else {
		randomName = fmt.Sprintf("v_%s.bin", randomName)
	}

	parent := DriveFolderID
	if cm.Mode == "self_hosted" {
		parent = "root"
	}

	driveFile := &drive.File{
		Name:    randomName,
		Parents: []string{parent},
	}
	if strings.TrimSpace(customKey) != "" {
		driveFile.Description = HashKey(customKey)
	}

	res, err := cm.Service.Files.Create(driveFile).Media(f).Do()
	if err != nil {
		return "", fmt.Errorf("unable to upload vault: %v", err)
	}

	fileID := res.Id

	if cm.Mode == "apm_public" {
		permission := &drive.Permission{
			Type: "anyone",
			Role: "reader",
		}
		_, err = cm.Service.Permissions.Create(fileID, permission).Do()
		if err != nil {
			return "", fmt.Errorf("unable to make file public: %v", err)
		}
	}

	return fileID, nil
}

func (cm *GoogleDriveManager) DownloadVault(fileID string) ([]byte, error) {
	return DownloadPublicVault(fileID)
}

func ExtractFileID(input string) string {
	if strings.Contains(input, "drive.google.com") {
		if strings.Contains(input, "/file/d/") {
			parts := strings.Split(input, "/file/d/")
			if len(parts) > 1 {
				idPart := parts[1]
				if idx := strings.Index(idPart, "/"); idx != -1 {
					return idPart[:idx]
				}
				if idx := strings.Index(idPart, "?"); idx != -1 {
					return idPart[:idx]
				}
				return idPart
			}
		}
		if strings.Contains(input, "id=") {
			parts := strings.Split(input, "id=")
			if len(parts) > 1 {
				idPart := parts[1]
				if idx := strings.Index(idPart, "&"); idx != -1 {
					return idPart[:idx]
				}
				return idPart
			}
		}
	}
	return input
}

// ResolveKeyToID prefers the hashed retrieval-key metadata path, then checks
// the legacy filename layout, and only finally treats the input as a direct ID.
func (cm *GoogleDriveManager) ResolveKeyToID(key string) (string, error) {
	parent := DriveFolderID
	if cm.Mode == "self_hosted" {
		parent = "root"
	}

	query := fmt.Sprintf("'%s' in parents and trashed = false", parent)
	list, err := cm.Service.Files.List().Q(query).Fields("files(id, name, description)").Do()
	if err != nil {
		return "", err
	}

	hashedKey := HashKey(key)
	for _, f := range list.Files {
		if f.Description == hashedKey {
			return f.Id, nil
		}
	}

	queryLegacy := fmt.Sprintf("name = 'vault_%s.bin' and '%s' in parents and trashed = false", key, parent)
	listLegacy, err := cm.Service.Files.List().Q(queryLegacy).Fields("files(id, name)").Do()
	if err == nil && len(listLegacy.Files) > 0 {
		return listLegacy.Files[0].Id, nil
	}

	if !strings.ContainsAny(key, " \t\r\n") && len(key) >= 16 && len(key) <= 128 {
		return key, nil
	}

	return "", fmt.Errorf("no vault found with key '%s'", key)
}

func DownloadPublicVault(input string) ([]byte, error) {
	fileID := ExtractFileID(input)

	if len(fileID) > 20 || strings.Contains(input, "drive.google.com") {
		url := fmt.Sprintf("https://drive.google.com/uc?export=download&id=%s", fileID)
		resp, err := http.Get(url)
		if err != nil {
			return nil, err
		}
		defer resp.Body.Close()
		if resp.StatusCode == http.StatusOK {
			return io.ReadAll(resp.Body)
		}
	}

	return nil, fmt.Errorf("direct download failed for '%s'. please use provider-specific retrieval.", input)
}

func (cm *GoogleDriveManager) SyncVault(vaultPath, fileID string) error {
	f, err := os.Open(vaultPath)
	if err != nil {
		return fmt.Errorf("unable to open vault file: %v", err)
	}
	defer f.Close()

	_, err = cm.Service.Files.Update(fileID, &drive.File{}).Media(f).Do()
	if err != nil {
		return fmt.Errorf("unable to sync vault: %v", err)
	}

	return nil
}

func (cm *GoogleDriveManager) DeleteVault(fileID string) error {
	err := cm.Service.Files.Delete(fileID).Do()
	if err != nil {
		return fmt.Errorf("unable to delete file %s: %v", fileID, err)
	}
	return nil
}

func HashKey(key string) string {
	h := sha256.New()
	h.Write([]byte(key))
	return hex.EncodeToString(h.Sum(nil))
}

func (cm *GoogleDriveManager) ListVaults() ([]string, error) {
	query := fmt.Sprintf("'%s' in parents and trashed = false", DriveFolderID)
	list, err := cm.Service.Files.List().Q(query).Do()
	if err != nil {
		return nil, fmt.Errorf("unable to list vaults: %v", err)
	}

	var vaults []string
	for _, f := range list.Files {
		vaults = append(vaults, fmt.Sprintf("%-30s ID: %s", f.Name, f.Id))
	}
	return vaults, nil
}

func PerformDriveAuth(credsJSON []byte) ([]byte, error) {
	config, err := google.ConfigFromJSON(credsJSON, drive.DriveFileScope)
	if err != nil {
		return nil, fmt.Errorf("unable to parse client secret: %v", err)
	}

	config.RedirectURL = "http://localhost:8080"

	authURL := config.AuthCodeURL("state-token", oauth2.AccessTypeOffline)
	fmt.Printf("\nWaiting for authentication in browser...\n")
	fmt.Printf("If the browser does not open, visit: %v\n", authURL)

	codeChan := make(chan string)
	errChan := make(chan error)

	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		code := r.URL.Query().Get("code")
		if code != "" {
			fmt.Fprintf(w, "Authentication successful! You can close this window and return to the terminal.")
			codeChan <- code
		} else {
			fmt.Fprintf(w, "Authentication failed. No code found.")
			errChan <- fmt.Errorf("no code in redirect")
		}
	})

	server := &http.Server{Addr: ":8080", Handler: mux}

	go func() {
		if err := server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			errChan <- err
		}
	}()

	// Attempt to open a browser, but keep the terminal flow usable when the
	// environment is headless or shell integration is unavailable.
	var errOpen error
	switch runtime.GOOS {
	case "linux":
		errOpen = exec.Command("xdg-open", authURL).Start()
	case "windows":
		errOpen = exec.Command("rundll32", "url.dll,FileProtocolHandler", authURL).Start()
	case "darwin":
		errOpen = exec.Command("open", authURL).Start()
	}
	if errOpen != nil {
		fmt.Println("Could not open browser automatically. Please open the link manually.")
	}

	var authCode string
	select {
	case authCode = <-codeChan:

	case err := <-errChan:
		return nil, err
	case <-time.After(5 * time.Minute):
		return nil, fmt.Errorf("authentication timed out")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	server.Shutdown(ctx)

	tok, err := config.Exchange(context.TODO(), authCode)
	if err != nil {
		return nil, fmt.Errorf("unable to retrieve token from web: %v", err)
	}

	return json.Marshal(tok)
}

var k_ = []byte("AaravMalooAPMSecureCloudSync2025!")

func h_(b []byte) []byte {
	res := make([]byte, len(b))
	for i, v := range b {
		val := byte(v - 13)
		val = (val >> 3) | (val << 5)
		res[i] = val ^ byte(i) ^ k_[i%len(k_)]
	}
	return res
}

func GetDefaultCreds() []byte {
	return h_([]byte{222, 31, 213, 109, 21, 238, 61, 69, 101, 37, 134, 216, 232, 54, 87, 133, 85, 93, 157, 254, 109, 54, 93, 197, 88, 223, 191, 119, 189, 213, 205, 213, 206, 207, 160, 40, 200, 32, 247, 104, 190, 168, 168, 69, 77, 69, 189, 222, 54, 78, 166, 158, 5, 88, 104, 118, 6, 37, 198, 120, 112, 216, 104, 222, 39, 117, 72, 63, 143, 159, 55, 254, 69, 47, 183, 175, 0, 166, 48, 168, 223, 183, 103, 47, 47, 56, 7, 95, 127, 159, 72, 191, 199, 143, 205, 23, 150, 230, 126, 13, 86, 182, 200, 40, 95, 32, 40, 72, 200, 168, 199, 63, 21, 126, 166, 72, 32, 64, 175, 184, 176, 88, 224, 207, 48, 16, 128, 222, 11, 27, 171, 139, 50, 97, 185, 25, 233, 194, 67, 187, 27, 131, 124, 2, 82, 194, 9, 138, 177, 185, 225, 196, 131, 179, 73, 105, 234, 177, 41, 67, 250, 2, 156, 188, 68, 105, 162, 234, 250, 114, 91, 122, 138, 122, 66, 33, 57, 163, 33, 218, 226, 140, 106, 252, 177, 178, 18, 226, 146, 243, 84, 146, 195, 73, 225, 171, 251, 67, 172, 91, 155, 123, 163, 219, 211, 171, 83, 33, 106, 42, 204, 180, 59, 67, 147, 9, 161, 186, 219, 187, 243, 123, 60, 177, 18, 60, 10, 242, 154, 242, 34, 75, 220, 164, 212, 170, 35, 44, 140, 138, 108, 11, 91, 235, 91, 162, 218, 18, 108, 92, 123, 12, 115, 212, 84, 43, 133, 61, 53, 175, 63, 80, 103, 165, 216, 151, 70, 85, 5, 158, 229, 238, 93, 109, 6, 24, 40, 48, 229, 13, 213, 229, 109, 32, 7, 247, 237, 109, 45, 192, 102, 134, 216, 160, 208, 200, 80, 205, 30, 94, 40, 206, 109, 38, 168, 150, 238, 69, 141, 141, 199, 248, 118, 248, 72, 246, 221, 38, 54, 214, 61, 254, 213, 127, 103, 253, 165, 229, 85, 198, 208, 135, 247, 255, 247, 192, 165, 69, 5, 232, 223, 63, 79, 175, 56, 197, 127, 149, 239, 110, 93, 56, 31, 48, 16, 38, 16, 47, 142, 246, 5, 94, 69, 239, 247, 15, 215, 152, 120, 40, 247, 176, 248, 159, 45, 189, 85, 128, 240, 96, 72, 96, 207, 144, 233, 106, 169, 34, 177, 209, 75, 137, 44, 217, 203, 3, 218, 241, 67, 27, 91, 146, 241, 241, 225, 193, 10, 82, 66, 2, 251, 58, 177, 161})
}

func GetDefaultToken() []byte {
	return h_([]byte{222, 31, 149, 21, 149, 118, 173, 205, 206, 157, 46, 142, 46, 142, 87, 191, 71, 221, 189, 32, 23, 175, 29, 39, 93, 21, 39, 182, 200, 47, 239, 144, 231, 167, 134, 237, 118, 222, 158, 104, 149, 174, 165, 231, 109, 191, 254, 53, 13, 102, 62, 158, 166, 61, 77, 77, 45, 125, 173, 237, 102, 255, 191, 7, 119, 102, 215, 95, 176, 128, 29, 207, 213, 143, 87, 199, 16, 191, 183, 63, 224, 152, 119, 216, 88, 62, 199, 223, 199, 85, 64, 176, 69, 88, 46, 215, 16, 13, 200, 120, 128, 175, 183, 80, 79, 160, 176, 87, 112, 128, 143, 200, 71, 72, 215, 152, 79, 199, 24, 103, 30, 64, 143, 255, 112, 87, 191, 157, 43, 20, 164, 179, 154, 89, 202, 10, 178, 250, 130, 249, 162, 171, 57, 108, 130, 161, 170, 154, 146, 11, 202, 113, 73, 139, 113, 18, 202, 154, 1, 202, 83, 243, 235, 163, 27, 2, 17, 153, 145, 153, 186, 66, 89, 178, 162, 177, 147, 201, 57, 154, 65, 188, 250, 209, 202, 146, 57, 58, 169, 154, 209, 177, 155, 66, 42, 17, 81, 250, 51, 204, 129, 217, 236, 180, 185, 84, 220, 131, 244, 51, 155, 170, 172, 44, 195, 195, 219, 131, 20, 187, 84, 3, 115, 75, 123, 60, 89, 209, 201, 89, 204, 188, 83, 91, 67, 131, 76, 251, 99, 75, 75, 33, 140, 203, 99, 75, 172, 251, 235, 114, 243, 68, 18, 164, 164, 209, 79, 94, 125, 13, 207, 72, 0, 152, 22, 86, 79, 207, 95, 192, 119, 135, 247, 93, 238, 78, 238, 78, 110, 13, 173, 229, 221, 224, 95, 143, 86, 253, 157, 94, 86, 158, 174, 214, 190, 16, 112, 125, 214, 238, 254, 166, 238, 222, 166, 182, 206, 237, 63, 31, 71, 40, 176, 40, 208, 214, 14, 189, 16, 37, 136, 208, 192, 0, 63, 165, 47, 190, 221, 150, 31, 104, 112, 120, 216, 55, 168, 240, 128, 160, 32, 39, 190, 79, 45, 168, 247, 55, 160, 111, 0, 15, 54, 246, 21, 94, 7, 79, 190, 221, 174, 62, 221, 143, 111, 215, 183, 224, 151, 239, 216, 248, 183, 143, 88, 93, 120, 127, 176, 223, 112, 216, 128, 87, 219, 18, 122, 225, 130, 89, 251, 65, 180, 155, 97, 147, 226, 57, 58, 66, 163, 156, 201, 233, 113, 162, 138, 138, 50, 25, 106, 177, 170, 113, 219, 148, 132, 106, 138, 202, 1, 130, 154, 68, 18, 234, 98, 130, 10, 227, 36, 124, 60, 100, 131, 68, 113, 108, 124, 115, 243, 59, 171, 140, 100, 68, 236, 124, 226, 209, 249, 129, 193, 250, 137, 241, 153, 83, 99, 235, 187, 131, 100, 195, 163, 219, 195, 236, 67, 68, 147, 195, 234, 170, 50, 250, 17, 73, 195})
}


func GetCloudProvider(providerName string, ctx context.Context, credsJSON []byte, tokenJSON []byte, mode string) (CloudProvider, error) {
	// Centralize provider bootstrap here so CLI, TUI, and MCP-triggered cloud
	// operations all inherit the same default credential/token resolution rules.
	switch strings.ToLower(providerName) {
	case "gdrive", "google":
		if len(credsJSON) == 0 {
			credsJSON = GetDefaultCreds()
		}
		if len(tokenJSON) == 0 {
			tokenJSON = GetDefaultToken()
		}
		if mode == "" {
			mode = "apm_public"
		}
		return NewGoogleDriveManager(ctx, credsJSON, tokenJSON, mode)
	case "github":
		if len(tokenJSON) == 0 {
			return nil, fmt.Errorf("github personal access token missing")
		}
		token, err := parseOAuthTokenOrRaw(tokenJSON)
		if err != nil {
			return nil, fmt.Errorf("github token parse failed: %v", err)
		}
		return NewGitHubManager(ctx, token)
	case "dropbox":
		if len(tokenJSON) == 0 {
			tokenJSON = GetDefaultDropboxToken()
		}
		token, err := parseOAuthTokenOrRaw(tokenJSON)
		if err != nil {
			return nil, fmt.Errorf("dropbox token parse failed: %v", err)
		}
		return NewDropboxManager(ctx, token)
	default:
		return nil, fmt.Errorf("unsupported cloud provider: %s", providerName)
	}
}

func parseOAuthTokenOrRaw(raw []byte) (string, error) {
	token := strings.TrimSpace(string(raw))
	if token == "" {
		return "", fmt.Errorf("empty token")
	}

	var tok oauth2.Token
	if err := json.Unmarshal(raw, &tok); err == nil && strings.TrimSpace(tok.AccessToken) != "" {
		return strings.TrimSpace(tok.AccessToken), nil
	}
	return token, nil
}

type DropboxManager struct {
	Client files.Client
	Token  string
}

func NewDropboxManager(ctx context.Context, token string) (*DropboxManager, error) {
	config := dropbox.Config{
		Token: token,
	}
	return &DropboxManager{
		Client: files.New(config),
		Token:  token,
	}, nil
}

func (cm *DropboxManager) UploadVault(vaultPath string, customKey string) (string, error) {
	f, err := os.Open(vaultPath)
	if err != nil {
		return "", err
	}
	defer f.Close()

	fileName := ""
	if strings.TrimSpace(customKey) != "" {
		fileName = fmt.Sprintf("/v_%s.bin", HashKey(customKey))
	} else {
		randomName, randErr := GenerateRandomHex(6)
		if randErr != nil {
			randomName = fmt.Sprintf("%d", time.Now().Unix())
		}
		fileName = fmt.Sprintf("/v_%s.bin", randomName)
	}

	arg := files.NewUploadArg(fileName)
	arg.Mode = &files.WriteMode{Tagged: dropbox.Tagged{Tag: "overwrite"}}

	_, err = cm.Client.Upload(arg, f)
	if err != nil {
		return "", fmt.Errorf("dropbox upload failed: %v", err)
	}
	return fileName, nil
}

func (cm *DropboxManager) DownloadVault(fileID string) ([]byte, error) {
	if !strings.HasPrefix(fileID, "/") {
		fileID = "/" + fileID
	}
	_, content, err := cm.Client.Download(files.NewDownloadArg(fileID))
	if err != nil {
		return nil, fmt.Errorf("dropbox download failed: %v", err)
	}
	defer content.Close()
	return io.ReadAll(content)
}

func (cm *DropboxManager) SyncVault(vaultPath, fileID string) error {
	f, err := os.Open(vaultPath)
	if err != nil {
		return err
	}
	defer f.Close()

	if !strings.HasPrefix(fileID, "/") {
		fileID = "/" + fileID
	}

	arg := files.NewUploadArg(fileID)
	arg.Mode = &files.WriteMode{Tagged: dropbox.Tagged{Tag: "overwrite"}}
	_, err = cm.Client.Upload(arg, f)
	if err != nil {
		return fmt.Errorf("dropbox sync failed: %v", err)
	}
	return nil
}

func (cm *DropboxManager) DeleteVault(fileID string) error {
	if !strings.HasPrefix(fileID, "/") {
		fileID = "/" + fileID
	}
	_, err := cm.Client.DeleteV2(files.NewDeleteArg(fileID))
	if err != nil {
		return fmt.Errorf("dropbox delete failed: %v", err)
	}
	return nil
}

func (cm *DropboxManager) ResolveKeyToID(key string) (string, error) {
	if strings.HasPrefix(key, "/") && strings.HasSuffix(strings.ToLower(key), ".bin") {
		return key, nil
	}

	target := fmt.Sprintf("/v_%s.bin", HashKey(key))
	_, err := cm.Client.GetMetadata(files.NewGetMetadataArg(target))
	if err == nil {
		return target, nil
	}
	return "", fmt.Errorf("no vault found for key '%s'", key)
}


func GetDefaultDropboxToken() []byte {
	return h_([]byte{158, 109, 255, 197, 239, 85, 14, 214, 125, 37, 166, 205, 70, 150, 230, 37, 101, 181, 182, 174, 77, 125, 191, 53, 158, 62, 237, 86, 213, 229, 32, 136, 206, 182, 101, 5, 190, 222, 109, 6, 88, 158, 6, 207, 149, 109, 30, 86, 149, 30, 197, 22, 117, 104, 174, 93, 254, 245, 213, 6, 133, 0, 199, 232, 71, 119, 119, 199, 229, 104, 16, 127, 103, 184, 31, 79, 127, 88, 199, 111, 160, 191, 149, 208, 144, 232, 88, 128, 223, 127, 247, 55, 208, 191, 22, 223, 77, 37, 176, 135, 136, 183, 136, 80, 173, 104, 158, 152, 136, 176, 79, 160, 72, 72, 23, 120, 159, 70, 63, 78, 248, 40, 215, 205, 158, 191, 55, 85, 243, 11, 235, 124, 18, 193, 170, 195, 65, 2, 137, 186, 26, 171, 129, 137, 170, 153, 153, 82, 33, 57, 67, 250, 201, 90, 2, 233, 201, 194, 59, 138, 19, 108, 44, 211, 186, 121, 105, 113, 233, 225, 114, 18, 9, 73, 66, 10, 185, 137, 169, 140, 185, 172, 161, 12, 41, 57, 1, 137, 225, 203, 145, 17, 219, 58, 105, 49, 105, 234, 2, 156, 60, 116, 4, 36, 107, 43, 164, 84, 163, 84, 236, 124, 243, 4, 76, 163, 145, 34, 65, 195, 36, 163, 52, 19, 28, 172, 18, 74, 44, 90, 98, 201, 234, 163, 12, 196, 131, 12, 43, 156, 92, 172, 28, 137, 4, 50, 228, 226, 43, 179, 243, 140, 227, 51, 90, 19, 135, 213, 141, 224, 232, 223, 39, 183, 0, 101, 149, 253, 95, 214, 22, 189, 53, 46, 149, 229, 166, 94, 238, 110, 158, 245, 190, 229, 31, 47, 86, 237, 21, 85, 221, 144, 64, 240, 62, 14, 64, 206, 205, 134, 254, 189, 126, 213, 141, 174, 173, 214, 141, 253, 183, 182, 80, 205, 149, 182, 221, 61, 221, 118, 168, 7, 144, 127, 199, 30, 125, 246, 214, 101, 120, 47, 239, 207, 112, 128, 23, 112, 184, 53, 151, 71, 224, 248, 87, 143, 127, 247, 8, 159, 175, 31, 167, 79, 224, 95, 207, 200, 118, 181, 245, 94, 166, 128, 16, 159, 48, 159, 239, 15, 159, 78, 224, 183, 168, 175, 213, 94, 80, 55, 136, 104, 103, 96, 227, 193, 26, 234, 186, 170, 17, 196, 3, 251, 116, 67, 26, 226, 58, 121, 81, 60, 3, 146, 186, 10, 162, 114, 124, 42, 123, 99, 217, 249, 225, 154, 81, 137, 25, 193, 161, 185, 60, 98, 122, 178, 251, 106, 115, 250, 82, 161, 233, 90, 217, 241, 132, 108, 233, 235, 227, 162, 129, 218, 97, 97, 42, 153, 35, 28, 27, 17, 155, 76, 92, 68, 3, 195, 129, 41, 250, 10, 227, 84, 75, 49, 3, 147, 121, 17, 27, 108, 130, 131, 244, 132, 180, 51, 123, 100, 99, 212, 43, 171, 68, 218, 115, 203, 178, 27, 202, 129, 114, 225, 218, 195, 131, 76, 179, 147, 28, 243, 106, 123, 132, 196, 164, 11, 12, 187, 59, 28, 71, 191, 46, 189, 165, 46, 37, 30, 173, 173, 61, 87, 103, 232, 101, 213, 253, 47, 149, 14, 167, 104, 22, 86, 70, 38, 166, 14, 69, 205, 79, 205, 214, 70, 38, 69, 232, 141, 29, 230, 87, 174, 94, 110, 151, 56, 150, 32, 47, 197, 6, 205, 142, 22, 94, 197, 206, 32, 222, 142, 61, 174, 214, 206, 23, 63, 151, 112, 255, 80, 24, 104, 173, 183, 88, 40, 48, 135, 133, 189, 239, 198, 215, 240, 191, 23, 168, 55, 191, 55, 176, 24, 136, 174, 32, 120, 23, 247, 31, 223, 40, 103, 231, 150, 80, 174, 208, 54, 231, 55, 117, 78, 197, 62, 69, 47, 55, 166, 22, 31, 13, 78, 16, 255, 31, 88, 216, 0, 201, 171, 81, 1, 26, 123, 17, 226, 89, 131, 234, 225, 234, 185, 11, 212, 180, 153, 35, 84, 25, 219, 17, 42, 203, 57, 90, 145, 1, 217, 84, 194, 179, 218, 202, 212, 17, 10, 145, 161, 65, 9, 129, 82, 242, 209, 178, 236, 107, 211, 227, 196, 27, 186, 9, 49, 18, 196, 10, 178, 76, 25, 186, 107, 155, 171, 20, 115, 83, 164, 67, 100, 220, 19, 148, 113, 19, 236, 57, 115, 244, 129, 187, 34, 114, 233, 156, 41, 12, 203, 140, 36, 59, 241, 172, 75, 20, 73, 203, 49, 187, 164, 251, 228, 67, 73, 194, 67, 115, 242, 49, 211, 180, 251, 130, 130, 50, 145, 25, 204, 235, 35, 36, 252, 241, 52, 20, 156, 125, 158, 104, 110, 53, 189, 86, 197, 54, 229, 240, 93, 127, 95, 206, 5, 239, 77, 238, 120, 168, 24, 192, 208, 253, 229, 142, 157, 38, 13, 94, 39, 102, 77, 223, 245, 166, 126, 69, 238, 110, 189, 126, 213, 222, 21, 109, 118, 149, 86, 157, 21, 15, 159, 56, 112, 231, 22, 222, 213, 157, 85, 158, 157, 16, 31, 200, 96, 8, 216, 135, 229, 111, 85, 109, 135, 238, 0, 205, 103, 255, 143, 112, 8, 221, 183, 109, 79, 254, 109, 247, 85, 199, 208, 87, 16, 40, 136, 246, 96, 197, 71, 229, 37, 71, 56, 192, 15, 111, 207, 79, 135, 120, 23, 143, 144, 32, 64, 14, 142, 117, 77, 126, 159, 215, 23, 79, 246, 12, 58, 242, 34, 3, 241, 169, 233, 202, 26, 49, 99, 9, 235, 161, 242, 226, 17, 19, 26, 3, 193, 19, 27, 107, 164, 195, 91, 108, 145, 179, 50, 60, 233, 228, 12, 10, 130, 11, 67, 74, 161, 65, 161, 138, 89, 233, 89, 209, 113, 249, 130, 34, 242, 177, 18, 83, 11, 27, 203, 12, 194, 138, 33, 19, 84, 211, 107, 123, 36, 11, 196, 35, 147, 163, 116, 228, 155, 219, 209, 228, 100, 12, 105, 28, 36, 33, 17, 35, 81, 137, 57, 17, 154, 75, 81, 212, 91, 227, 100, 123, 123, 12, 250, 49, 228, 115, 203, 75, 220, 155, 114, 115, 76, 68, 82, 123, 180, 156, 139, 156, 171, 41, 234, 249, 249, 66, 155, 30, 206, 127, 157, 21, 165, 125, 141, 134, 254, 149, 21, 64, 230, 237, 14, 126, 22, 80, 206, 22, 151, 103, 22, 190, 71, 206, 245, 175, 7, 96, 64, 207, 214, 238, 70, 13, 158, 62, 8, 125, 182, 215, 86, 215, 222, 168, 133, 126, 13, 190, 21, 190, 200, 150, 93, 110, 38, 198, 80, 48, 0, 239, 47, 30, 224, 189, 47, 149, 215, 7, 149, 72, 111, 64, 39, 64, 135, 160, 72, 32, 192, 120, 167, 151, 64, 200, 135, 152, 248, 200, 23, 111, 21, 110, 38, 214, 205, 181, 159, 232, 135, 135, 167, 55, 95, 174, 191, 223, 168, 159, 143, 160, 62, 182, 32, 248, 240, 200, 247, 223, 46, 231, 136, 151, 118, 30, 109, 105, 44, 68, 236, 66, 242, 17, 89, 177, 98, 81, 171, 49, 180, 241, 209, 234, 43, 42, 218, 26, 218, 218, 10, 178, 178, 114, 234, 114, 65, 131, 60, 252, 98, 35, 178, 90, 92, 9, 162, 116, 2, 218, 186, 164, 188, 243, 217, 241, 147, 57, 28, 114, 66, 100, 226, 249, 68, 98, 100, 11, 57, 10, 129, 186, 73, 18, 26, 243, 244, 107, 65, 44, 235, 188, 84, 44, 225, 132, 242, 108, 51, 154, 73, 132, 172, 115, 252, 212, 163, 27, 203, 219, 219, 36, 60, 172, 242, 169, 28, 244, 1, 124, 131, 147, 75, 58, 193, 27, 211, 51, 196, 171, 36, 91, 201, 52, 180, 178, 35, 98, 212, 179, 219, 147, 147, 83, 187, 189, 102, 200, 15, 63, 136, 55, 102, 102, 86, 167, 111, 182, 53, 222, 133, 77, 37, 21, 190, 85, 189, 222, 142, 125, 165, 5, 54, 46, 22, 102, 62, 181, 246, 157, 200, 48, 56, 32, 135, 165, 56, 110, 181, 102, 165, 61, 21, 117, 222, 54, 174, 150, 175, 101, 126, 29, 165, 206, 157, 94, 29, 149, 21, 232, 136, 21, 120, 182, 230, 215, 182, 133, 223, 5, 117, 64, 159, 112, 176, 223, 216, 200, 183, 246, 175, 96, 8, 239, 237, 151, 128, 239, 175, 40, 167, 55, 167, 126, 199, 64, 246, 141, 246, 133, 248, 7, 88, 232, 96, 134, 165, 200, 54, 142, 78, 15, 152, 0, 191, 48, 143, 239, 23, 88, 248, 64, 231, 170, 17, 186, 137, 74, 34, 60, 4, 123, 97, 65, 65, 242, 123, 217, 194, 185, 27, 115, 97, 122, 66, 90, 105, 114, 115, 186, 251, 203, 169, 242, 10, 1, 74, 2, 35, 138, 220, 9, 66, 20, 34, 3, 4, 243, 185, 10, 106, 113, 49, 73, 170, 202, 122, 162, 163, 1, 3, 193, 177, 26, 18, 124, 130, 188, 100, 187, 107, 228, 137, 36, 43})
}

func PerformDropboxAuth(config oauth2.Config) ([]byte, error) {
	authURL := config.AuthCodeURL("state-token", oauth2.AccessTypeOffline)
	fmt.Printf("\nWaiting for Dropbox authentication...\n")
	fmt.Printf("Visit: %v\n", authURL)

	codeChan := make(chan string)
	errChan := make(chan error)

	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		code := r.URL.Query().Get("code")
		if code != "" {
			fmt.Fprintf(w, "Authentication successful!")
			codeChan <- code
		} else {
			errChan <- fmt.Errorf("no code found")
		}
	})

	server := &http.Server{Addr: ":8080", Handler: mux}
	go server.ListenAndServe()

	switch os.Getenv("OS") {
	case "Windows_NT":
		exec.Command("rundll32", "url.dll,FileProtocolHandler", authURL).Start()
	}

	var authCode string
	select {
	case authCode = <-codeChan:
	case err := <-errChan:
		return nil, err
	case <-time.After(5 * time.Minute):
		return nil, fmt.Errorf("timed out")
	}

	server.Shutdown(context.Background())
	tok, err := config.Exchange(context.TODO(), authCode)
	if err != nil {
		return nil, err
	}
	return json.Marshal(tok)
}

type GitHubManager struct {
	Client *github.Client
	Token  string
	Repo   string
	Ctx    context.Context
}

func NewGitHubManager(ctx context.Context, token string) (*GitHubManager, error) {
	ts := oauth2.StaticTokenSource(
		&oauth2.Token{AccessToken: token},
	)
	tc := oauth2.NewClient(ctx, ts)
	client := github.NewClient(tc)

	return &GitHubManager{
		Client: client,
		Token:  token,
		Ctx:    ctx,
	}, nil
}

func (gm *GitHubManager) SetRepo(repo string) {
	gm.Repo = repo
}

func (gm *GitHubManager) UploadVault(vaultPath string, customKey string) (string, error) {
	content, err := os.ReadFile(vaultPath)
	if err != nil {
		return "", err
	}

	repoParts := strings.Split(gm.Repo, "/")
	if len(repoParts) != 2 {
		return "", fmt.Errorf("invalid repo format, expected owner/repo")
	}
	owner, repo := repoParts[0], repoParts[1]

	_, _, err = gm.Client.Repositories.Get(gm.Ctx, owner, repo)
	if err != nil {
		newRepo := &github.Repository{
			Name:        github.String(repo),
			Private:     github.Bool(true),
			Description: github.String("APM Secure Vault Storage"),
		}
		_, _, err = gm.Client.Repositories.Create(gm.Ctx, "", newRepo)
		if err != nil {
			return "", fmt.Errorf("failed to create private repo: %v", err)
		}
	}

	fileContent, _, _, err := gm.Client.Repositories.GetContents(gm.Ctx, owner, repo, "vault.dat", nil)
	var sha *string
	if err == nil && fileContent != nil {
		sha = fileContent.SHA
	}

	opts := &github.RepositoryContentFileOptions{
		Message: github.String("update vault"),
		Content: content,
		SHA:     sha,
	}

	_, _, err = gm.Client.Repositories.UpdateFile(gm.Ctx, owner, repo, "vault.dat", opts)
	if err != nil {
		_, _, err = gm.Client.Repositories.CreateFile(gm.Ctx, owner, repo, "vault.dat", opts)
		if err != nil {
			return "", fmt.Errorf("failed to upload vault to github: %v", err)
		}
	}

	return gm.Repo, nil
}

func (gm *GitHubManager) DownloadVault(fileID string) ([]byte, error) {
	repoParts := strings.Split(fileID, "/")
	if len(repoParts) != 2 {
		return nil, fmt.Errorf("invalid repo format in fileID")
	}
	owner, repo := repoParts[0], repoParts[1]

	fileContent, _, _, err := gm.Client.Repositories.GetContents(gm.Ctx, owner, repo, "vault.dat", nil)
	if err != nil {
		return nil, fmt.Errorf("failed to get vault from github: %v", err)
	}

	content, err := fileContent.GetContent()
	if err != nil {
		return nil, err
	}

	return []byte(content), nil
}

func (gm *GitHubManager) SyncVault(vaultPath, fileID string) error {
	_, err := gm.UploadVault(vaultPath, "")
	return err
}

func (gm *GitHubManager) DeleteVault(fileID string) error {
	repoParts := strings.Split(fileID, "/")
	if len(repoParts) != 2 {
		return fmt.Errorf("invalid repo format")
	}
	owner, repo := repoParts[0], repoParts[1]

	_, err := gm.Client.Repositories.Delete(gm.Ctx, owner, repo)
	return err
}

func (gm *GitHubManager) ResolveKeyToID(key string) (string, error) {

	return key, nil
}

