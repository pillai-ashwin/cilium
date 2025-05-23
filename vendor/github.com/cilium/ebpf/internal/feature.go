package internal

import (
	"errors"
	"fmt"
	"runtime"
	"sync"

	"github.com/cilium/ebpf/internal/platform"
)

// ErrNotSupported indicates that a feature is not supported.
var ErrNotSupported = errors.New("not supported")

// ErrNotSupportedOnOS indicates that a feature is not supported on the current
// operating system.
var ErrNotSupportedOnOS = fmt.Errorf("%w on %s", ErrNotSupported, runtime.GOOS)

// UnsupportedFeatureError is returned by FeatureTest() functions.
type UnsupportedFeatureError struct {
	// The minimum version required for this feature.
	//
	// On Linux this refers to the mainline kernel version, on other platforms
	// to the version of the runtime.
	//
	// Used for the error string, and for sanity checking during testing.
	MinimumVersion Version

	// The name of the feature that isn't supported.
	Name string
}

func (ufe *UnsupportedFeatureError) Error() string {
	if ufe.MinimumVersion.Unspecified() {
		return fmt.Sprintf("%s not supported", ufe.Name)
	}
	return fmt.Sprintf("%s not supported (requires >= %s)", ufe.Name, ufe.MinimumVersion)
}

// Is indicates that UnsupportedFeatureError is ErrNotSupported.
func (ufe *UnsupportedFeatureError) Is(target error) bool {
	return target == ErrNotSupported
}

// FeatureTest caches the result of a [FeatureTestFn].
//
// Fields should not be modified after creation.
type FeatureTest struct {
	// The name of the feature being detected.
	Name string
	// Version in the form Major.Minor[.Patch].
	Version string
	// The feature test itself.
	Fn FeatureTestFn

	mu     sync.RWMutex
	done   bool
	result error
}

// FeatureTestFn is used to determine whether the kernel supports
// a certain feature.
//
// The return values have the following semantics:
//
//	err == ErrNotSupported: the feature is not available
//	err == nil: the feature is available
//	err != nil: the test couldn't be executed
type FeatureTestFn func() error

// NewFeatureTest is a convenient way to create a single [FeatureTest].
//
// versions specifies in which version of a BPF runtime a feature appeared.
// The format is "GOOS:Major.Minor[.Patch]". GOOS may be omitted when targeting
// Linux. Returns [ErrNotSupportedOnOS] if there is no version specified for the
// current OS.
func NewFeatureTest(name string, fn FeatureTestFn, versions ...string) func() error {
	version, err := platform.SelectVersion(versions)
	if err != nil {
		return func() error { return err }
	}

	if version == "" {
		return func() error {
			// We don't return an UnsupportedFeatureError here, since that will
			// trigger version checks which don't make sense.
			return fmt.Errorf("%s: %w", name, ErrNotSupportedOnOS)
		}
	}

	ft := &FeatureTest{
		Name:    name,
		Version: version,
		Fn:      fn,
	}

	return ft.execute
}

// execute the feature test.
//
// The result is cached if the test is conclusive.
//
// See [FeatureTestFn] for the meaning of the returned error.
func (ft *FeatureTest) execute() error {
	ft.mu.RLock()
	result, done := ft.result, ft.done
	ft.mu.RUnlock()

	if done {
		return result
	}

	ft.mu.Lock()
	defer ft.mu.Unlock()

	// The test may have been executed by another caller while we were
	// waiting to acquire ft.mu.
	if ft.done {
		return ft.result
	}

	err := ft.Fn()
	if err == nil {
		ft.done = true
		return nil
	}

	if errors.Is(err, ErrNotSupported) {
		var v Version
		if ft.Version != "" {
			v, err = NewVersion(ft.Version)
			if err != nil {
				return fmt.Errorf("feature %s: %w", ft.Name, err)
			}
		}

		ft.done = true
		ft.result = &UnsupportedFeatureError{
			MinimumVersion: v,
			Name:           ft.Name,
		}

		return ft.result
	}

	// We couldn't execute the feature test to a point
	// where it could make a determination.
	// Don't cache the result, just return it.
	return fmt.Errorf("detect support for %s: %w", ft.Name, err)
}

// FeatureMatrix groups multiple related feature tests into a map.
//
// Useful when there is a small number of discrete features which are known
// at compile time.
//
// It must not be modified concurrently with calling [FeatureMatrix.Result].
type FeatureMatrix[K comparable] map[K]*FeatureTest

// Result returns the outcome of the feature test for the given key.
//
// It's safe to call this function concurrently.
//
// Always returns [ErrNotSupportedOnOS] on Windows.
func (fm FeatureMatrix[K]) Result(key K) error {
	ft, ok := fm[key]
	if !ok {
		return fmt.Errorf("no feature probe for %v", key)
	}

	if platform.IsWindows {
		return fmt.Errorf("%s: %w", ft.Name, ErrNotSupportedOnOS)
	}

	return ft.execute()
}

// FeatureCache caches a potentially unlimited number of feature probes.
//
// Useful when there is a high cardinality for a feature test.
type FeatureCache[K comparable] struct {
	mu       sync.RWMutex
	newTest  func(K) *FeatureTest
	features map[K]*FeatureTest
}

func NewFeatureCache[K comparable](newTest func(K) *FeatureTest) *FeatureCache[K] {
	return &FeatureCache[K]{
		newTest:  newTest,
		features: make(map[K]*FeatureTest),
	}
}

func (fc *FeatureCache[K]) Result(key K) error {
	if platform.IsWindows {
		return fmt.Errorf("feature probe for %v: %w", key, ErrNotSupportedOnOS)
	}

	// NB: Executing the feature test happens without fc.mu taken.
	return fc.retrieve(key).execute()
}

func (fc *FeatureCache[K]) retrieve(key K) *FeatureTest {
	fc.mu.RLock()
	ft := fc.features[key]
	fc.mu.RUnlock()

	if ft != nil {
		return ft
	}

	fc.mu.Lock()
	defer fc.mu.Unlock()

	if ft := fc.features[key]; ft != nil {
		return ft
	}

	ft = fc.newTest(key)
	fc.features[key] = ft
	return ft
}
