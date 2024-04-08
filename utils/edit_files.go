package utils

import (
	"bufio"
	"fmt"
	"os"
	"strings"
)

func InsertLineToFile(fileName, line string) error {
	// Open the file in read mode to check for duplicates
	file, err := os.OpenFile(fileName, os.O_RDONLY, os.FileMode(ReadFilePermissionCode))
	if err != nil {
		return err
	}
	defer file.Close()

	// Create a scanner to read the file line by line
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		existingLine := scanner.Text()

		// Check if the line already exists in the file
		if existingLine == line {
			fmt.Println("Duplicate line found. Skipping insertion.")
			return nil
		}
	}

	// Open the file in append mode to add the new line
	file, err = os.OpenFile(fileName, os.O_APPEND|os.O_WRONLY, os.FileMode(ReadFilePermissionCode))
	if err != nil {
		return err
	}
	defer file.Close()

	// Write the new line to the file
	_, err = file.WriteString(line + "\n")
	if err != nil {
		return err
	}
	return nil
}

func RemoveLineFromFile(fileName, lineToRemove string) error {
	// Open the input file in read mode
	file, err := os.OpenFile(fileName, os.O_RDWR, os.FileMode(ReadFilePermissionCode))
	if err != nil {
		return err
	}
	defer file.Close()

	// Create a scanner to read the file line by line
	scanner := bufio.NewScanner(file)
	var lines []string

	// Read lines into a slice, excluding the line to be removed
	for scanner.Scan() {
		line := scanner.Text()
		if strings.TrimSpace(line) != lineToRemove {
			lines = append(lines, line)
		}
	}

	// Truncate the file to remove its content
	err = file.Truncate(0)
	if err != nil {
		return err
	}

	// Seek to the beginning of the file
	_, err = file.Seek(0, 0)
	if err != nil {
		return err
	}

	// Write the updated lines back to the file
	writer := bufio.NewWriter(file)
	for _, line := range lines {
		_, errR := writer.WriteString(line + "\n")
		if errR != nil {
			return errR
		}
	}

	err = writer.Flush()
	if err != nil {
		return err
	}
	return nil
}
