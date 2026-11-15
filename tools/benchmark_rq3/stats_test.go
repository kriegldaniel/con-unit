package main

import (
	"math"
	"testing"
	"time"
)

// tCDF is an independent implementation of the Student t distribution
// function through the regularized incomplete beta function (continued
// fraction of Numerical Recipes). It is used to check the t table without
// trusting the table itself.
func tCDF(t float64, df int) float64 {
	v := float64(df)
	x := v / (v + t*t)
	p := 0.5 * regIncBeta(x, v/2, 0.5)
	if t > 0 {
		return 1 - p
	}
	return p
}

func regIncBeta(x, a, b float64) float64 {
	if x <= 0 {
		return 0
	}
	if x >= 1 {
		return 1
	}
	lg := func(z float64) float64 { v, _ := math.Lgamma(z); return v }
	bt := math.Exp(lg(a+b) - lg(a) - lg(b) + a*math.Log(x) + b*math.Log(1-x))
	if x < (a+1)/(a+b+2) {
		return bt * betacf(x, a, b) / a
	}
	return 1 - bt*betacf(1-x, b, a)/b
}

func betacf(x, a, b float64) float64 {
	const maxIter, eps, fpmin = 500, 3e-16, 1e-300
	qab, qap, qam := a+b, a+1, a-1
	c, d := 1.0, 1-qab*x/qap
	if math.Abs(d) < fpmin {
		d = fpmin
	}
	d = 1 / d
	h := d
	for m := 1; m <= maxIter; m++ {
		fm := float64(m)
		m2 := 2 * fm
		aa := fm * (b - fm) * x / ((qam + m2) * (a + m2))
		d = 1 + aa*d
		if math.Abs(d) < fpmin {
			d = fpmin
		}
		c = 1 + aa/c
		if math.Abs(c) < fpmin {
			c = fpmin
		}
		d = 1 / d
		h *= d * c
		aa = -(a + fm) * (qab + fm) * x / ((a + m2) * (qap + m2))
		d = 1 + aa*d
		if math.Abs(d) < fpmin {
			d = fpmin
		}
		c = 1 + aa/c
		if math.Abs(c) < fpmin {
			c = fpmin
		}
		d = 1 / d
		del := d * c
		h *= del
		if math.Abs(del-1) < eps {
			break
		}
	}
	return h
}

// tQuantile finds the upper 2.5% quantile of the t distribution by bisection.
func tQuantile(df int) float64 {
	lo, hi := 0.0, 200.0
	for i := 0; i < 200; i++ {
		mid := (lo + hi) / 2
		if tCDF(mid, df) < 0.975 {
			lo = mid
		} else {
			hi = mid
		}
	}
	return (lo + hi) / 2
}

func TestTTableAgainstIndependentQuantiles(t *testing.T) {
	// Sanity of the reference implementation with textbook values.
	for df, want := range map[int]float64{1: 12.7062, 5: 2.5706, 9: 2.2622, 30: 2.0423} {
		if got := tQuantile(df); math.Abs(got-want) > 6e-5 {
			t.Fatalf("reference quantile df=%d = %.5f, want %.4f", df, got, want)
		}
	}
	for df := 1; df <= tTableMaxDF; df++ {
		want := tQuantile(df)
		got := TCritical95(df)
		// The table is rounded to four decimals.
		if math.Abs(got-want) > 5.1e-5 {
			t.Errorf("TCritical95(%d) = %.4f, independent quantile %.5f", df, got, want)
		}
	}
}

func TestTCriticalKnownValues(t *testing.T) {
	cases := []struct {
		df   int
		want float64
	}{
		{1, 12.7062}, {2, 4.3027}, {4, 2.7764},
		{5, 2.5706},  // n = 6: the old code used 2.776
		{6, 2.4469},  // n = 7
		{7, 2.3646},  // n = 8
		{8, 2.3060},  // n = 9
		{9, 2.2622},  // n = 10
		{10, 2.2281}, // n = 11: the old code used the normal value 1.96
		{19, 2.0930}, {29, 2.0452}, {30, 2.0423},
	}
	for _, tc := range cases {
		if got := TCritical95(tc.df); got != tc.want {
			t.Errorf("TCritical95(%d) = %v, want %v", tc.df, got, tc.want)
		}
	}
	if got := TCritical95(31); math.Abs(got-1.959964) > 1e-9 {
		t.Errorf("beyond the table the normal value is used, got %v", got)
	}
	if got := TCritical95(1000); math.Abs(got-1.959964) > 1e-9 {
		t.Errorf("TCritical95(1000) = %v", got)
	}
	if TCritical95(0) != 0 || TCritical95(-3) != 0 {
		t.Error("no interval exists below one degree of freedom")
	}
	for df := 2; df <= tTableMaxDF; df++ {
		if TCritical95(df) >= TCritical95(df-1) {
			t.Errorf("t critical values must decrease with df, violated at %d", df)
		}
	}
}

func TestComputeStatsOneToTen(t *testing.T) {
	values := []float64{10, 1, 9, 2, 8, 3, 7, 4, 6, 5} // unsorted on purpose
	orig := append([]float64(nil), values...)
	st := ComputeStats(values, "ms")
	for i := range values {
		if values[i] != orig[i] {
			t.Fatal("ComputeStats must not modify its input")
		}
	}
	approx := func(name string, got, want float64) {
		t.Helper()
		if math.Abs(got-want) > 1e-9 {
			t.Errorf("%s = %.10f, want %.10f", name, got, want)
		}
	}
	if st.N != 10 || st.Unit != "ms" {
		t.Fatalf("N=%d unit=%s", st.N, st.Unit)
	}
	approx("mean", st.Mean, 5.5)
	approx("median", st.Median, 5.5)
	approx("q1", st.Q1, 3.25) // type 7
	approx("q3", st.Q3, 7.75)
	approx("iqr", st.IQR, 4.5)
	approx("min", st.Min, 1)
	approx("max", st.Max, 10)
	approx("sample sd", st.StdDev, math.Sqrt(82.5/9)) // 3.0276503541
	if !st.CIDefined {
		t.Fatal("CI must be defined for n = 10")
	}
	approx("t crit", st.TCrit, 2.2622)
	approx("ci half width", st.CIHalfWidth, 2.2622*math.Sqrt(82.5/9)/math.Sqrt(10))
	approx("ci low", st.CILow, st.Mean-st.CIHalfWidth)
	approx("ci high", st.CIHigh, st.Mean+st.CIHalfWidth)
}

func TestComputeStatsSampleStandardDeviation(t *testing.T) {
	st := ComputeStats([]float64{2, 4, 4, 4, 5, 5, 7, 9}, "x")
	// Population SD would be exactly 2. The sample form is sqrt(32/7).
	if math.Abs(st.StdDev-math.Sqrt(32.0/7.0)) > 1e-12 {
		t.Errorf("sd = %v, want the n-1 form %v", st.StdDev, math.Sqrt(32.0/7.0))
	}
}

func TestComputeStatsSmallSamples(t *testing.T) {
	if st := ComputeStats(nil, "ms"); st.N != 0 || st.CIDefined {
		t.Errorf("empty sample: %+v", st)
	}
	one := ComputeStats([]float64{42}, "ms")
	if one.N != 1 || one.Mean != 42 || one.Median != 42 || one.Q1 != 42 || one.Q3 != 42 || one.CIDefined {
		t.Errorf("single observation: %+v", one)
	}
	two := ComputeStats([]float64{1, 3}, "ms")
	if !two.CIDefined || two.TCrit != 12.7062 {
		t.Errorf("n=2 must use df=1: %+v", two)
	}
	if want := 12.7062 * math.Sqrt2 / math.Sqrt2; math.Abs(two.CIHalfWidth-want) > 1e-9 {
		t.Errorf("n=2 half width = %v, want %v", two.CIHalfWidth, want)
	}
}

func TestConfidenceIntervalUsesCorrectDegreesOfFreedom(t *testing.T) {
	// For n between 6 and 9 and above 10 the old table was wrong.
	for n := 2; n <= 40; n++ {
		values := make([]float64, n)
		for i := range values {
			values[i] = float64(i)
		}
		st := ComputeStats(values, "x")
		want := TCritical95(n-1) * st.StdDev / math.Sqrt(float64(n))
		if math.Abs(st.CIHalfWidth-want) > 1e-12 {
			t.Errorf("n=%d: half width %v, want %v", n, st.CIHalfWidth, want)
		}
	}
}

func TestQuantile(t *testing.T) {
	sorted := []float64{1, 2, 3, 4}
	cases := []struct{ p, want float64 }{{0, 1}, {0.25, 1.75}, {0.5, 2.5}, {0.75, 3.25}, {1, 4}}
	for _, tc := range cases {
		if got := Quantile(sorted, tc.p); math.Abs(got-tc.want) > 1e-12 {
			t.Errorf("Quantile(%v) = %v, want %v", tc.p, got, tc.want)
		}
	}
	if Quantile(nil, 0.5) != 0 || Quantile([]float64{7}, 0.9) != 7 {
		t.Error("degenerate samples")
	}
}

func TestDurationStatsKeepsNanosecondResolution(t *testing.T) {
	// The old code truncated to whole milliseconds with Duration.Milliseconds.
	ds := []time.Duration{1_500_001 * time.Nanosecond, 1_500_003 * time.Nanosecond}
	st := DurationStats(ds)
	if st.Unit != "ns" {
		t.Errorf("unit = %s", st.Unit)
	}
	if st.Mean != 1_500_002 || st.Min != 1_500_001 || st.Max != 1_500_003 {
		t.Errorf("mean/min/max = %v/%v/%v, want 1500002/1500001/1500003", st.Mean, st.Min, st.Max)
	}
	sub := DurationStats([]time.Duration{250 * time.Microsecond, 750 * time.Microsecond})
	if sub.Median != 500_000 {
		t.Errorf("sub-millisecond median = %v ns, want 500000", sub.Median)
	}
}
