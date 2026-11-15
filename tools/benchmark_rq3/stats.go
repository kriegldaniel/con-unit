package main

import (
	"math"
	"sort"
	"time"
)

// zCrit95 is the two-sided 95% critical value of the standard normal
// distribution. It replaces the Student t value for more than tTableMaxDF
// degrees of freedom.
const zCrit95 = 1.959964

// tTableMaxDF is the largest degrees of freedom with a tabulated t value.
const tTableMaxDF = 30

// tCrit95 holds the two-sided 95% critical values of Student's t distribution
// (upper 2.5% quantile) for 1 to 30 degrees of freedom. Index 0 is unused.
var tCrit95 = [tTableMaxDF + 1]float64{
	0,
	12.7062, 4.3027, 3.1824, 2.7764, 2.5706, // df 1-5
	2.4469, 2.3646, 2.3060, 2.2622, 2.2281, // df 6-10
	2.2010, 2.1788, 2.1604, 2.1448, 2.1314, // df 11-15
	2.1199, 2.1098, 2.1009, 2.0930, 2.0860, // df 16-20
	2.0796, 2.0739, 2.0687, 2.0639, 2.0595, // df 21-25
	2.0555, 2.0518, 2.0484, 2.0452, 2.0423, // df 26-30
}

// TCritical95 returns the two-sided 95% critical value for df degrees of
// freedom: the Student t quantile for df 1 to 30 and the normal quantile
// beyond. It returns 0 for df below 1, where no interval exists.
//
// The normal value is slightly anti-conservative for df between 31 and 120
// (for example 2.0395 instead of 1.9600 at df 31). The protocol asks for at
// least 10 timed trials, so df is 9 or more and usually below 31.
func TCritical95(df int) float64 {
	switch {
	case df < 1:
		return 0
	case df <= tTableMaxDF:
		return tCrit95[df]
	default:
		return zCrit95
	}
}

// Stats summarizes a sample. Every value is in Unit.
//
// Median and quartiles use linear interpolation between order statistics
// (type 7, the default of R and NumPy). The standard deviation is the sample
// form with n-1. The confidence interval is for the mean, two-sided 95%,
// Student t with n-1 degrees of freedom. It is undefined for fewer than two
// observations, and CIDefined is false then.
type Stats struct {
	N           int     `json:"n"`
	Unit        string  `json:"unit"`
	Mean        float64 `json:"mean"`
	StdDev      float64 `json:"std_dev"`
	Median      float64 `json:"median"`
	Q1          float64 `json:"q1"`
	Q3          float64 `json:"q3"`
	IQR         float64 `json:"iqr"`
	Min         float64 `json:"min"`
	Max         float64 `json:"max"`
	CIDefined   bool    `json:"ci_defined"`
	TCrit       float64 `json:"t_crit,omitempty"`
	CIHalfWidth float64 `json:"ci_half_width,omitempty"`
	CILow       float64 `json:"ci_low,omitempty"`
	CIHigh      float64 `json:"ci_high,omitempty"`
}

// ComputeStats summarizes values. The input is not modified.
func ComputeStats(values []float64, unit string) Stats {
	n := len(values)
	st := Stats{N: n, Unit: unit}
	if n == 0 {
		return st
	}
	sorted := append([]float64(nil), values...)
	sort.Float64s(sorted)

	sum := 0.0
	for _, v := range sorted {
		sum += v
	}
	st.Mean = sum / float64(n)
	st.Min = sorted[0]
	st.Max = sorted[n-1]
	st.Median = Quantile(sorted, 0.5)
	st.Q1 = Quantile(sorted, 0.25)
	st.Q3 = Quantile(sorted, 0.75)
	st.IQR = st.Q3 - st.Q1

	if n > 1 {
		ss := 0.0
		for _, v := range sorted {
			d := v - st.Mean
			ss += d * d
		}
		st.StdDev = math.Sqrt(ss / float64(n-1))
		st.TCrit = TCritical95(n - 1)
		st.CIHalfWidth = st.TCrit * st.StdDev / math.Sqrt(float64(n))
		st.CILow = st.Mean - st.CIHalfWidth
		st.CIHigh = st.Mean + st.CIHalfWidth
		st.CIDefined = true
	}
	return st
}

// DurationStats summarizes durations in nanoseconds. A float64 holds integer
// nanoseconds exactly up to 2^53 ns (about 104 days), so no resolution is lost.
func DurationStats(durations []time.Duration) Stats {
	values := make([]float64, len(durations))
	for i, d := range durations {
		values[i] = float64(d.Nanoseconds())
	}
	return ComputeStats(values, "ns")
}

// Quantile returns the p quantile of an ascending sorted sample by linear
// interpolation (type 7). It returns 0 for an empty sample.
func Quantile(sorted []float64, p float64) float64 {
	n := len(sorted)
	switch {
	case n == 0:
		return 0
	case n == 1:
		return sorted[0]
	}
	if p <= 0 {
		return sorted[0]
	}
	if p >= 1 {
		return sorted[n-1]
	}
	h := float64(n-1) * p
	lo := math.Floor(h)
	frac := h - lo
	i := int(lo)
	if i+1 >= n {
		return sorted[n-1]
	}
	return sorted[i] + frac*(sorted[i+1]-sorted[i])
}
