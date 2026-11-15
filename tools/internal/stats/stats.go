// Package stats holds the small set of statistical helpers shared by the
// evaluation tooling (exporter, preview, adjudication, agreement).
//
// Conventions fixed by docs/ANALYSIS_PLAN.md:
//   - proportions carry a Wilson score interval at 95 percent
//   - standard deviations are the sample form (divisor n-1)
//   - undefined quantities are reported through an explicit ok flag, never
//     through NaN or a division by zero
package stats

import (
	"math"
	"sort"
)

// Z95 is the two-sided 95 percent quantile of the standard normal
// distribution.
const Z95 = 1.959963984540054

// Wilson returns the Wilson score interval for k successes out of n trials at
// the 95 percent level. ok is false when n is not positive, in which case no
// interval exists and lo and hi are zero.
func Wilson(k, n int) (lo, hi float64, ok bool) {
	return WilsonZ(k, n, Z95)
}

// WilsonZ is Wilson with an explicit normal quantile.
func WilsonZ(k, n int, z float64) (lo, hi float64, ok bool) {
	if n <= 0 || k < 0 || k > n {
		return 0, 0, false
	}
	nf := float64(n)
	p := float64(k) / nf
	z2 := z * z
	denom := 1 + z2/nf
	centre := (p + z2/(2*nf)) / denom
	half := z * math.Sqrt(p*(1-p)/nf+z2/(4*nf*nf)) / denom
	lo = centre - half
	hi = centre + half
	// The closed forms reach the boundary exactly for k = 0 and k = n;
	// clamp to remove floating point residue.
	if k == 0 || lo < 0 {
		lo = 0
	}
	if k == n || hi > 1 {
		hi = 1
	}
	return lo, hi, true
}

// Proportion returns k/n and false when n is not positive.
func Proportion(k, n int) (float64, bool) {
	if n <= 0 {
		return 0, false
	}
	return float64(k) / float64(n), true
}

// Mean returns the arithmetic mean and false for an empty slice.
func Mean(xs []float64) (float64, bool) {
	if len(xs) == 0 {
		return 0, false
	}
	sum := 0.0
	for _, x := range xs {
		sum += x
	}
	return sum / float64(len(xs)), true
}

// SampleSD returns the sample standard deviation (divisor n-1). ok is false
// for fewer than two observations.
func SampleSD(xs []float64) (float64, bool) {
	if len(xs) < 2 {
		return 0, false
	}
	m, _ := Mean(xs)
	ss := 0.0
	for _, x := range xs {
		d := x - m
		ss += d * d
	}
	return math.Sqrt(ss / float64(len(xs)-1)), true
}

// Quantile returns the q-quantile (0 <= q <= 1) of an ascending sorted slice
// using linear interpolation between order statistics (R type 7). It returns
// 0 for an empty slice.
func Quantile(sorted []float64, q float64) float64 {
	n := len(sorted)
	if n == 0 {
		return 0
	}
	if q <= 0 {
		return sorted[0]
	}
	if q >= 1 {
		return sorted[n-1]
	}
	pos := q * float64(n-1)
	lo := int(math.Floor(pos))
	frac := pos - float64(lo)
	if lo+1 >= n {
		return sorted[n-1]
	}
	return sorted[lo] + frac*(sorted[lo+1]-sorted[lo])
}

// Summary is a descriptive summary of a sample.
type Summary struct {
	N      int     `json:"n"`
	Min    float64 `json:"min"`
	Q1     float64 `json:"q1"`
	Median float64 `json:"median"`
	Q3     float64 `json:"q3"`
	Max    float64 `json:"max"`
	Mean   float64 `json:"mean"`
	// SD is the sample standard deviation. It is only meaningful when
	// SDOK is true (n >= 2).
	SD   float64 `json:"sd"`
	SDOK bool    `json:"sd_defined"`
}

// Summarize computes a Summary. An empty sample yields the zero Summary with
// N = 0.
func Summarize(xs []float64) Summary {
	s := Summary{N: len(xs)}
	if len(xs) == 0 {
		return s
	}
	sorted := append([]float64(nil), xs...)
	sort.Float64s(sorted)
	s.Min = sorted[0]
	s.Max = sorted[len(sorted)-1]
	s.Q1 = Quantile(sorted, 0.25)
	s.Median = Quantile(sorted, 0.5)
	s.Q3 = Quantile(sorted, 0.75)
	s.Mean, _ = Mean(xs)
	s.SD, s.SDOK = SampleSD(xs)
	return s
}

// KappaResult is the outcome of an agreement computation between two raters
// (or two runs) over the same items.
type KappaResult struct {
	N         int     `json:"n"`
	Agree     int     `json:"agree"`
	Agreement float64 `json:"agreement"` // observed proportion of agreement
	Expected  float64 `json:"expected"`  // agreement expected by chance
	Kappa     float64 `json:"kappa"`
	// Defined is false when kappa cannot be computed: no items, or chance
	// agreement equal to one (both raters used a single identical category).
	Defined bool `json:"kappa_defined"`
}

// Kappa computes Cohen's kappa for two equally long label slices. Labels are
// compared as given. The result has Defined == false when n == 0 or when the
// expected agreement is 1, so callers never see NaN.
func Kappa(a, b []string) KappaResult {
	n := len(a)
	if len(b) < n {
		n = len(b)
	}
	res := KappaResult{N: n}
	if n == 0 {
		return res
	}
	countA := map[string]int{}
	countB := map[string]int{}
	for i := 0; i < n; i++ {
		countA[a[i]]++
		countB[b[i]]++
		if a[i] == b[i] {
			res.Agree++
		}
	}
	nf := float64(n)
	res.Agreement = float64(res.Agree) / nf
	// Sum in sorted label order so the result is bit-for-bit reproducible.
	labels := make([]string, 0, len(countA))
	for label := range countA {
		labels = append(labels, label)
	}
	sort.Strings(labels)
	for _, label := range labels {
		res.Expected += (float64(countA[label]) / nf) * (float64(countB[label]) / nf)
	}
	if res.Expected >= 1 {
		return res
	}
	res.Kappa = (res.Agreement - res.Expected) / (1 - res.Expected)
	res.Defined = true
	return res
}
