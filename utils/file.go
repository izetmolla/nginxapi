package utils

import (
	"bufio"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
)

var (
	ReadFilePermissionCode = 0644
	mkdirPerm              = 0o700
)

func CreateTextFile(filePath, content string, params ...any) (err error) {
	var f *os.File
	f, err = os.Create(filePath)
	if err != nil {
		defer f.Close()
		return err
	}

	if _, err = fmt.Fprintf(f, content, params...); err != nil {
		defer f.Close()
		return err
	} else {
		defer f.Close()
		return nil
	}
}
func CreateNonExistingFolder(path string) error {
	if _, err := os.Stat(path); os.IsNotExist(err) {
		return os.MkdirAll(path, fs.FileMode(mkdirPerm))
	} else if err != nil {
		return err
	}
	return nil
}

func CreateCustomDirectories(cd string) {
	if !IsExistOnDisk(cd) {
		MakeDirs(cd)
		MakeDirs(
			filepath.Join(cd, "hosts"),
			filepath.Join(cd, "temlates"),
			filepath.Join(cd, "ssl"),
		)
	}
	_, err := CheckOrCreateSystemFile(filepath.Join(cd, "main.conf"))
	if err != nil {
		fmt.Println("Erro on CreateCustomDirectories: ", err.Error())
	}
}

func IsExistOnDisk(files ...string) bool {
	_, errfileExist := os.Stat(filepath.Join(files...))
	return !os.IsNotExist(errfileExist)
}

func MakeDirs(arg ...string) {
	for _, dirPath := range arg {
		if _, err := os.Stat(dirPath); os.IsNotExist(err) {
			if err := os.MkdirAll(dirPath, os.ModePerm); err != nil {
				fmt.Println("Error creating dir:", err.Error())
			}
		}
	}
}

func CheckOrCreateSystemFile(filepathName string) (string, error) {
	if !IsExistOnDisk(filepathName) {
		err := os.MkdirAll(filepath.Dir(filepathName), os.ModePerm)
		if err != nil {
			return filepathName, err
		}
		file, err := os.Create(filepathName)
		if err != nil {
			return filepathName, err
		}
		defer file.Close()
	}
	return filepathName, nil
}

func CreateFoldersPaths(folderPath string) string {
	if IsExistOnDisk(folderPath) {
		return folderPath
	} else {
		MakeDirs(
			folderPath,
			filepath.Join(folderPath, "config"),
			filepath.Join(folderPath, "ssl"),
		)
		return folderPath
	}
}

func StoreNginxFile(fileName, content string, params ...any) (err error) {
	var f *os.File
	f, err = os.Create(fileName)
	if err != nil {
		defer f.Close()
		return err
	}

	if _, err = fmt.Fprintf(f, content, params...); err != nil {
		defer f.Close()
		return err
	} else {
		defer f.Close()
		return nil
	}
}

func DeleteHost(filename string) error {
	return os.RemoveAll(filename)
}

func CopyFile(src, dst string) error {
	sourceFileStat, err := os.Stat(src)
	if err != nil {
		return err
	}

	if !sourceFileStat.Mode().IsRegular() {
		return fmt.Errorf("%s is not a regular file", src)
	}

	source, err := os.Open(src)
	if err != nil {
		return err
	}
	defer source.Close()

	destination, err := os.Create(dst)
	if err != nil {
		return err
	}
	defer destination.Close()
	_, err = io.Copy(destination, source)
	return err
}

func ChangeConfigByParam(configFilePath, paramKey, newParamValue string) error {
	// Open the NGINX configuration file for reading
	file, err := os.Open(configFilePath)
	if err != nil {
		return err
	}
	defer file.Close()

	// Create a scanner to read the file line by line
	scanner := bufio.NewScanner(file)

	// Create a variable to hold the modified configuration
	var modifiedConfig []string

	// Iterate through each line of the file
	for scanner.Scan() {
		line := scanner.Text()

		// Check if the line contains the parameter key
		if strings.Contains(line, paramKey) {
			// Replace the old parameter value with the new one
			newLine := strings.Replace(line, getValueAfterKey(line, paramKey), fmt.Sprintf(" %s;\n", newParamValue), 1)
			modifiedConfig = append(modifiedConfig, newLine)
		} else {
			// If the line does not contain the parameter key, keep it unchanged
			modifiedConfig = append(modifiedConfig, line)
		}
	}

	// Check for errors during scanning
	err = scanner.Err()
	if err != nil {
		return err
	}

	// Open the NGINX configuration file for writing (truncate)
	outputFile, err := os.Create(configFilePath)
	if err != nil {
		return err
	}
	defer outputFile.Close()

	// Write the modified configuration back to the file
	for _, line := range modifiedConfig {
		_, err := outputFile.WriteString(line + "\n")
		if err != nil {
			return err
		}
	}

	return nil
}
