package nginxapi

import (
	"fmt"
	"path/filepath"

	"github.com/izetmolla/nginxapi/nginx"
	"github.com/izetmolla/nginxapi/ssl"
	"github.com/izetmolla/nginxapi/utils"
)

func (nginx *NGINX) Get(query interface{}, args ...interface{}) (tx *NGINX) {

	return
}

func (ng *NGINX) Create(data *nginx.HostData) (res map[string]interface{}, err error) {
	if data.HostID == "" {
		return nil, fmt.Errorf("hostid is required")
	}
	if utils.IsExistOnDisk(ng.ConfigPath, "hosts", data.HostID) {
		return nil, fmt.Errorf("hostid %s exist, try another hostid", data.HostID)
	}
	return ng.Update(data.HostID, data)
}

func (ng *NGINX) Update(hostID string, data *nginx.HostData) (res map[string]interface{}, err error) {
	if data.HostID == "" {
		data.HostID = hostID
	}
	err = ng.formatHostVariables(data)
	if err != nil {
		return res, err
	}
	hostPath := utils.CreateFoldersPaths(ng.configPath("hosts", hostID))
	if !ssl.CheckForSelfSSL(hostPath, data.ServerNames[0]) {
		_ = ssl.GenerateSelfSSL(data.ServerNames[0], hostPath, "Proxy Manager")
	}
	_ = backupCurrentConfig(hostPath)
	locations := formatLocations(data.Locations)
	to := includeOptions(map[string]interface{}{})
	bo := includeOptions(map[string]interface{}{})

	err = setHTTPNginxFile(
		filepath.Join(hostPath, "config"),
		data.ForceHTTPS, to,
		includeListener(data.ListenIP, data.ListenPORT, "", "http"),
		utils.ArrToStr(data.ServerNames), locations, bo, filepath.Join(hostPath, "config"))
	if err != nil {
		return nil, err
	}
	if data.HTTPS {
		err = setHTTPSNginxFile(
			filepath.Join(hostPath, "config"), to,
			includeListener(data.ListenIP, data.ListenPORT, "ssl", "https"),
			utils.ArrToStr(data.ServerNames),
			includeSslConf(hostPath, data.ServerNames[0], ssl.GetLastSSLType(hostPath)),
			locations, bo, filepath.Join(hostPath, "config"),
		)
		if err != nil {
			return nil, err
		}
	}

	err = utils.SetConfigData(hostPath, ng.ConfigExtension, utils.StructToMap(ng.hostDataToObject(data)))
	if err != nil {
		return nil, err
	}

	err = ng.checkAndUpdate(hostID, data.ServerNames, data.HTTPS, data.LetsEncrypt)
	if err != nil {
		return nil, err
	}

	return map[string]interface{}{
		"hostPath": hostPath,
		"domains":  data.ServerNames,
	}, err
}

func (ng *NGINX) SetCustomSSL(hostID, dm, key, cert string) (paths map[string]string, err error) {
	sslPath := filepath.Join(ng.ConfigPath, "hosts", hostID, "ssl", "custom", "certificates")
	err = utils.CreateTextFile(filepath.Join(sslPath, fmt.Sprintf("%s.cert", dm)), cert)
	if err != nil {
		return nil, err
	}
	err = utils.CreateTextFile(filepath.Join(sslPath, fmt.Sprintf("%s.key", dm)), cert)
	if err != nil {
		return nil, err
	}
	err = ng.updateSSLType(hostID, dm, "custom")
	if err != nil {
		return nil, err
	}

	return map[string]string{
		"certificate": filepath.Join(sslPath, fmt.Sprintf("%s.cert", dm)),
		"key":         filepath.Join(sslPath, fmt.Sprintf("%s.key", dm)),
	}, nil
}
