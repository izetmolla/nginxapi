package nginxapi

import (
	"fmt"
	"path/filepath"
	"strings"

	"github.com/izetmolla/nginxapi/utils"
)

func (nginx *NGINX) Status() (string, error) {
	if outstr, errstr, err := utils.ExecApp("nginx", "-t"); err != nil {
		return fmt.Sprintf("%s %s", outstr, errstr), err
	} else {
		msg := fmt.Sprintf("%s %s", outstr, errstr)
		if strings.Contains(msg, "[warn]") || strings.Contains(msg, "[emerg]") {
			return "", fmt.Errorf("%s", msg)
		}
		if strings.Contains(msg, "[alert]") || strings.Contains(msg, "[error]") {
			return "", fmt.Errorf("%s", msg)
		}

		return fmt.Sprintf("%s %s", outstr, errstr), nil
	}
}

func (nginx *NGINX) Restart() (m string, e error) {
	_, stdErrCheck, e := utils.ExecApp("nginx", "-t")
	if e != nil {
		return stdErrCheck, e
	}
	msg, stdErrReload, e := utils.ExecApp("nginx", "-s", "reload")
	if e != nil {
		return stdErrReload, e
	}
	return msg, nil
}

func (nginx *NGINX) Reload() (msg string, err error) {
	msg, stdErrCheck, err := utils.ExecApp("nginx", "-t")
	if err != nil {
		return msg, fmt.Errorf("%s", stdErrCheck)
	}
	msg, stdErrReload, err := utils.ExecApp("nginx", "-s", "reload", "-c", "/etc/nginx/nginx.conf")
	if err != nil {
		return msg, fmt.Errorf("%s", stdErrReload)
	}
	return msg, nil
}

func (nginx *NGINX) RemoveHost(hostID string) error {
	if err := utils.RemoveLineFromFile(
		filepath.Join(nginx.ConfigPath, "main.conf"),
		fmt.Sprintf("include %s/*.conf;", filepath.Join(nginx.ConfigPath, "hosts", "config", hostID)),
	); err != nil {
		return err
	}
	if err := utils.DeleteHost(filepath.Join(nginx.ConfigPath, "hosts", hostID)); err != nil {
		return err
	}
	return nil
}
