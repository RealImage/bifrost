package bfcli

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"os"

	tea "github.com/charmbracelet/bubbletea"
	charmfs "github.com/charmbracelet/charm/fs"
	"github.com/google/uuid"
)

type cadata struct {
	Label       string
	Namespace   uuid.UUID
	Certificate []byte
	PrivateKey  []byte
}

const casFilePath = "bifrost/cas.json"

func (m model) initFS() (model, error) {
	if m.fs != nil {
		return m, nil
	}
	var err error
	m.fs, err = charmfs.NewFS()
	return m, err
}

func (m model) loadCAs() tea.Msg {
	m, err := m.initFS()
	if err != nil {
		return fmt.Errorf("error initialising charmfs: %w", err)
	}
	file, err := m.fs.Open(casFilePath)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return m.storeCAs()
		}
		return fmt.Errorf("error opening file: %w", err)
	}
	defer file.Close()
	if err := json.NewDecoder(file).Decode(&m.cas); err != nil {
		return fmt.Errorf("error decoding CAs JSON file: %w", err)
	}
	return "Loaded"
}

func (m model) storeCAs() tea.Msg {
	m, err := m.initFS()
	if err != nil {
		return err
	}
	tmpFile, err := os.CreateTemp("", "cas.json")
	if err != nil {
		return err
	}
	defer tmpFile.Close()
	if err := json.NewEncoder(tmpFile).Encode(m.cas); err != nil {
		return err
	}
	if _, err := tmpFile.Seek(0, 0); err != nil {
		return err
	}
	if err := m.fs.WriteFile(casFilePath, tmpFile); err != nil {
		return err
	}
	return "Saved"
}

func (m model) newCA() tea.Msg {
	m, err := m.initFS()
	if err != nil {
		return err
	}
	if m.caLabel.Value() == "" {
		return "Label cannot be empty"
	}

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return err
	}
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		return err
	}
	template := &x509.Certificate{}
	certDER, err := x509.CreateCertificate(rand.Reader, template, template, key.Public(), key)
	if err != nil {
		return err
	}
	m.cas = append(m.cas, cadata{
		Label:       m.caLabel.Value(),
		Namespace:   uuid.New(),
		Certificate: certDER,
		PrivateKey:  keyDER,
	})
	return m.storeCAs()
}

func (m model) startIssuer() tea.Msg {
	return uuid.UUID{}
}

func (m model) startBouncer() tea.Msg {
	return uuid.UUID{}
}
