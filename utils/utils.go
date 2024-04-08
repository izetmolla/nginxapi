package utils

import (
	"bufio"
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strings"

	"gopkg.in/yaml.v2"
)

func ArrToStr(objArr []string) string {
	str := ""
	for i := 0; i < len(objArr); i++ {
		str += fmt.Sprintf("%s ", objArr[i])
	}
	return str
}

func GetContentByParam(configFilePath, paramKey string) (string, error) {
	// Open the NGINX configuration file for reading
	file, err := os.Open(configFilePath)
	if err != nil {
		return "", err
	}
	defer file.Close()
	scanner := bufio.NewScanner(file)
	// Iterate through each line of the file
	for scanner.Scan() {
		line := scanner.Text()
		// Check if the line contains the parameter key
		if strings.Contains(line, paramKey) {
			return getValueAfterKey(line, paramKey), nil
		}
	}

	// Check for errors during scanning
	err = scanner.Err()
	if err != nil {
		return "", err
	}
	return "", nil
}

// getValueAfterKey extracts the value after the parameter key in a line
func getValueAfterKey(line, key string) string {
	// Find the index of the parameter key
	index := strings.Index(line, key)
	if index == -1 {
		return ""
	}

	// Get the substring after the parameter key
	value := line[index+len(key):]
	// Trim any leading or trailing whitespace
	value = strings.TrimSpace(value)

	return value
}

func SetConfigData(fp, confExt string, data map[string]interface{}) error {
	fileSource := filepath.Join(fp, fmt.Sprintf("config.%s", confExt))
	if !IsExistOnDisk(fileSource) {
		return Marshal(fileSource, data)
	}
	if d, err := Unmarshal(fileSource); err != nil {
		return err
	} else {
		return Marshal(fileSource, UpdateOrInsertMap(d, data))
	}
}

func Marshal(filename string, data interface{}) error {
	fd, err := os.Create(filename)
	if err != nil {
		return (err)
	}
	defer fd.Close()

	switch ext := filepath.Ext(filename); ext {
	case ".json": //nolint:goconst
		encoder := json.NewEncoder(fd)
		encoder.SetIndent("", "    ")
		return encoder.Encode(data)
	case ".yml", ".yaml": //nolint:goconst
		encoder := yaml.NewEncoder(fd)
		return encoder.Encode(data)
	default:
		return fmt.Errorf("invalid format: %s", ext)
	}
}

func Unmarshal(filename string) (data map[string]interface{}, err error) {
	fd, err := os.Open(filename)
	if err != nil {
		return nil, err
	}
	defer fd.Close()

	switch ext := filepath.Ext(filename); ext {
	case ".json":
		_ = json.NewDecoder(fd).Decode(&data)
		return data, nil
	case ".yml", ".yaml":
		_ = yaml.NewDecoder(fd).Decode(&data)
		return data, nil
	default:
		return nil, fmt.Errorf("invalid format: %s", ext)
	}
}

func UpdateOrInsertMap(obj1, obj2 map[string]interface{}) map[string]interface{} {
	for key, value := range obj2 {
		// Check if the key exists in obj1
		if _, ok := obj1[key]; !ok {
			// Key does not exist, insert it
			obj1[key] = value
		} else {
			// Key exists, update its value
			switch v := value.(type) {
			case map[string]interface{}:
				// If the value is a map, recursively update
				if v2, ok := obj1[key].(map[string]interface{}); ok {
					UpdateOrInsertMap(v2, v)
				} else {
					// If the existing value is not a map, overwrite it
					obj1[key] = value
				}
			default:
				// For non-map values, overwrite the existing value
				obj1[key] = value
			}
		}
	}

	return obj1
}

// Function to convert struct to map
func StructToMap(s interface{}) map[string]interface{} {
	// Create an empty map
	result := make(map[string]interface{})

	// Get the type and value of the struct
	sType := reflect.TypeOf(s)
	sValue := reflect.ValueOf(s)

	// Iterate over struct fields
	for i := 0; i < sType.NumField(); i++ {
		// Get field name
		fieldName := sType.Field(i).Name

		// Get field value
		fieldValue := sValue.Field(i).Interface()

		// Add field name and value to the map
		result[fieldName] = fieldValue
	}

	return result
}
func ExecApp(name string, arg ...string) (par1, par2 string, err error) {
	cmd := exec.Command(name, arg...)
	var outb, errb bytes.Buffer
	cmd.Stdout = &outb
	cmd.Stderr = &errb
	err = cmd.Run()
	return outb.String(), errb.String(), err
}

func ReloadNginx() (msg string, err error) {
	msg, stdErrCheck, err := ExecApp("nginx", "-t")
	if err != nil {
		return msg, fmt.Errorf("%s %s", stdErrCheck, msg)
	}
	msg, stdErrReload, err := ExecApp("nginx", "-s", "reload", "-c", "/etc/nginx/nginx.conf")
	if err != nil {
		return msg, fmt.Errorf("%s %s", stdErrReload, msg)
	}
	return msg, nil
}
