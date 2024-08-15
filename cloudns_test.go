package cloudns

import (
	"reflect"
	"testing"
)

func TestCreateActivateFailover(t *testing.T) {
	t.Run("Ping check", func(t *testing.T) {

		validApiAccess := &Apiaccess{
			Authid:       24325,
			Authpassword: "123456",
		}
		expectedResult := activatefailover{
			Domain:           "testzone.bg",
			RecordId:         "518569025",
			FailoverType:     1,
			MainIP:           "192.168.0.1",
			Timeout:          3,
			LatencyLimit:     5,
			BackupIp1:        "192.168.0.5",
			UpEventHandler:   2,
			DownEventHandler: 2,
			NotificationMail: "venkoul99@gmail.com",
		}

		afInstance := activatefailover{
			Domain:           "testzone.bg",
			RecordId:         "518569025",
			FailoverType:     1,
			MainIP:           "192.168.0.1",
			Timeout:          3,
			LatencyLimit:     5,
			BackupIp1:        "192.168.0.5",
			UpEventHandler:   2,
			DownEventHandler: 2,
			NotificationMail: "venkoul99@gmail.com",
		}

		result, err := afInstance.Create(validApiAccess)
		if err != nil {
			t.Errorf("Expected no error, got %v", err)
		}

		if !reflect.DeepEqual(result, expectedResult) {
			t.Errorf("Expected result %v, got %v", expectedResult, result)
		}
	})

	t.Run("HTTP check", func(t *testing.T) {

		validApiAccess := &Apiaccess{
			Authid:       24325,
			Authpassword: "123456",
		}
		expectedResult := activatefailover{
			Domain:           "testzone.bg",
			RecordId:         "518752375",
			FailoverType:     4,
			MainIP:           "192.168.0.2",
			Host:             "radioflix.org",
			Port:             443,
			Path:             "somepath",
			HttpRequestType:  "GET",
			UpEventHandler:   1,
			DownEventHandler: 1,
			NotificationMail: "venkoul99@gmail.com",
		}

		afInstance := activatefailover{
			Domain:           "testzone.bg",
			RecordId:         "518752375",
			FailoverType:     4,
			MainIP:           "192.168.0.2",
			Host:             "radioflix.org",
			Port:             443,
			Path:             "somepath",
			HttpRequestType:  "GET",
			UpEventHandler:   1,
			DownEventHandler: 1,
			NotificationMail: "venkoul99@gmail.com",
		}

		result, err := afInstance.Create(validApiAccess)
		if err != nil {
			t.Errorf("Expected no error, got %v", err)
		}

		if !reflect.DeepEqual(result, expectedResult) {
			t.Errorf("Expected result %v, got %v", expectedResult, result)
		}
	})

}
