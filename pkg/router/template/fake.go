package templaterouter

func NewFakeTemplateRouter() *templateRouter {
	_logClusterCodePath()
	defer _logClusterCodePath()
	fakeCertManager, _ := newSimpleCertificateManager(newFakeCertificateManagerConfig(), &fakeCertWriter{})
	return &templateRouter{state: map[string]ServiceAliasConfig{}, serviceUnits: make(map[string]ServiceUnit), certManager: fakeCertManager, rateLimitedCommitFunction: nil}
}
func (r *templateRouter) FakeReloadHandler() {
	_logClusterCodePath()
	defer _logClusterCodePath()
	r.lock.Lock()
	defer r.lock.Unlock()
	r.stateChanged = false
	return
}

type fakeCertWriter struct {
	addedCerts	[]string
	deletedCerts	[]string
}

func (fcw *fakeCertWriter) clear() {
	_logClusterCodePath()
	defer _logClusterCodePath()
	fcw.addedCerts = make([]string, 0)
	fcw.deletedCerts = make([]string, 0)
}
func (fcw *fakeCertWriter) WriteCertificate(directory string, id string, cert []byte) error {
	_logClusterCodePath()
	defer _logClusterCodePath()
	fcw.addedCerts = append(fcw.addedCerts, directory+id)
	return nil
}
func (fcw *fakeCertWriter) DeleteCertificate(directory, id string) error {
	_logClusterCodePath()
	defer _logClusterCodePath()
	fcw.deletedCerts = append(fcw.deletedCerts, directory+id)
	return nil
}
func newFakeCertificateManagerConfig() *certificateManagerConfig {
	_logClusterCodePath()
	defer _logClusterCodePath()
	return &certificateManagerConfig{certKeyFunc: generateCertKey, caCertKeyFunc: generateCACertKey, destCertKeyFunc: generateDestCertKey, certDir: certDir, caCertDir: caCertDir}
}
