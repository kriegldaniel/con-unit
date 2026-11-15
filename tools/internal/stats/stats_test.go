package stats

import (
	"math"
	"testing"
)

func near(a, b, tol float64) bool { return math.Abs(a-b) <= tol }

func TestWilsonReferenceValues(t *testing.T) {
	// Reference values computed independently from the closed-form Wilson
	// score interval with z = 1.959964.
	cases := []struct {
		k, n   int
		lo, hi float64
	}{
		{0, 10, 0.0, 0.2775},
		{5, 10, 0.2366, 0.7634},
		{10, 10, 0.7225, 1.0},
		{1, 100, 0.0018, 0.0545},
		{77, 94, 0.7293, 0.8839},
		{7, 94, 0.0365, 0.1458},
		{1, 1, 0.2065, 1.0},
		{0, 1, 0.0, 0.7935},
		{30, 100, 0.2189, 0.3958},
	}
	for _, c := range cases {
		lo, hi, ok := Wilson(c.k, c.n)
		if !ok {
			t.Fatalf("Wilson(%d,%d) not ok", c.k, c.n)
		}
		if !near(lo, c.lo, 5e-5) || !near(hi, c.hi, 5e-5) {
			t.Errorf("Wilson(%d,%d) = [%.4f, %.4f], want [%.4f, %.4f]", c.k, c.n, lo, hi, c.lo, c.hi)
		}
	}
}

func TestWilsonBoundaries(t *testing.T) {
	lo, hi, ok := Wilson(0, 50)
	if !ok || lo != 0 {
		t.Errorf("Wilson(0,50) lower bound = %v ok=%v, want exactly 0", lo, ok)
	}
	if hi <= 0 || hi >= 1 {
		t.Errorf("Wilson(0,50) upper bound %v outside (0,1)", hi)
	}
	lo, hi, ok = Wilson(50, 50)
	if !ok || hi != 1 {
		t.Errorf("Wilson(50,50) upper bound = %v ok=%v, want exactly 1", hi, ok)
	}
	if lo <= 0 || lo >= 1 {
		t.Errorf("Wilson(50,50) lower bound %v outside (0,1)", lo)
	}
}

func TestWilsonEmptyDenominator(t *testing.T) {
	for _, c := range [][2]int{{0, 0}, {3, 0}, {-1, 5}, {6, 5}} {
		lo, hi, ok := Wilson(c[0], c[1])
		if ok || lo != 0 || hi != 0 {
			t.Errorf("Wilson(%d,%d) = [%v,%v] ok=%v, want not ok and zero bounds", c[0], c[1], lo, hi, ok)
		}
	}
}

func TestWilsonContainsPointEstimate(t *testing.T) {
	for n := 1; n <= 60; n++ {
		for k := 0; k <= n; k++ {
			lo, hi, ok := Wilson(k, n)
			p := float64(k) / float64(n)
			if !ok || lo > p+1e-12 || hi < p-1e-12 || lo < 0 || hi > 1 {
				t.Fatalf("Wilson(%d,%d) = [%v,%v] does not bracket p=%v inside [0,1]", k, n, lo, hi, p)
			}
		}
	}
}

func TestSampleSDUsesNMinusOne(t *testing.T) {
	// Population SD of this sample is 2; the sample SD is sqrt(32/7).
	xs := []float64{2, 4, 4, 4, 5, 5, 7, 9}
	sd, ok := SampleSD(xs)
	if !ok {
		t.Fatal("SampleSD not ok for n=8")
	}
	want := math.Sqrt(32.0 / 7.0)
	if !near(sd, want, 1e-12) {
		t.Errorf("SampleSD = %v, want %v", sd, want)
	}
	if _, ok := SampleSD([]float64{3}); ok {
		t.Error("SampleSD must be undefined for a single observation")
	}
	if _, ok := SampleSD(nil); ok {
		t.Error("SampleSD must be undefined for an empty sample")
	}
}

func TestQuantileAndSummary(t *testing.T) {
	xs := []float64{9, 1, 5, 3, 7}
	s := Summarize(xs)
	if s.N != 5 || s.Min != 1 || s.Max != 9 || s.Median != 5 {
		t.Errorf("unexpected summary: %+v", s)
	}
	if s.Q1 != 3 || s.Q3 != 7 {
		t.Errorf("quartiles = %v, %v; want 3, 7", s.Q1, s.Q3)
	}
	if !near(s.Mean, 5, 1e-12) || !s.SDOK {
		t.Errorf("mean/sd unexpected: %+v", s)
	}
	// Input must not be reordered.
	if xs[0] != 9 || xs[4] != 7 {
		t.Errorf("Summarize modified its input: %v", xs)
	}
	even := Summarize([]float64{1, 2, 3, 4})
	if !near(even.Median, 2.5, 1e-12) || !near(even.Q1, 1.75, 1e-12) || !near(even.Q3, 3.25, 1e-12) {
		t.Errorf("even-sized quantiles unexpected: %+v", even)
	}
	empty := Summarize(nil)
	if empty.N != 0 || empty.SDOK {
		t.Errorf("empty summary unexpected: %+v", empty)
	}
	single := Summarize([]float64{4})
	if single.N != 1 || single.SDOK || single.Median != 4 {
		t.Errorf("single-value summary unexpected: %+v", single)
	}
}

func TestKappaClassicExample(t *testing.T) {
	// 2x2 table: yes/yes 20, yes/no 5, no/yes 10, no/no 15.
	var a, b []string
	add := func(x, y string, n int) {
		for i := 0; i < n; i++ {
			a = append(a, x)
			b = append(b, y)
		}
	}
	add("yes", "yes", 20)
	add("yes", "no", 5)
	add("no", "yes", 10)
	add("no", "no", 15)
	r := Kappa(a, b)
	if !r.Defined || r.N != 50 || r.Agree != 35 {
		t.Fatalf("unexpected result: %+v", r)
	}
	if !near(r.Agreement, 0.7, 1e-12) || !near(r.Expected, 0.5, 1e-12) || !near(r.Kappa, 0.4, 1e-12) {
		t.Errorf("agreement/expected/kappa = %v/%v/%v, want 0.7/0.5/0.4", r.Agreement, r.Expected, r.Kappa)
	}
}

func TestKappaPerfectAndChance(t *testing.T) {
	a := []string{"TP", "FP", "TP", "UNDECIDABLE", "FP"}
	r := Kappa(a, a)
	if !r.Defined || !near(r.Kappa, 1, 1e-12) || r.Agreement != 1 {
		t.Errorf("perfect agreement: %+v", r)
	}
	// Rater B always says "x" while rater A splits evenly: kappa is 0.
	r = Kappa([]string{"x", "y", "x", "y"}, []string{"x", "x", "x", "x"})
	if !r.Defined || !near(r.Kappa, 0, 1e-12) || !near(r.Agreement, 0.5, 1e-12) {
		t.Errorf("chance-level agreement: %+v", r)
	}
}

func TestKappaUndefinedCases(t *testing.T) {
	if r := Kappa(nil, nil); r.Defined || r.N != 0 {
		t.Errorf("empty input must be undefined: %+v", r)
	}
	// Both raters use one identical category: expected agreement is 1.
	r := Kappa([]string{"TP", "TP", "TP"}, []string{"TP", "TP", "TP"})
	if r.Defined || r.Agreement != 1 || math.IsNaN(r.Kappa) {
		t.Errorf("single-category input must be undefined without NaN: %+v", r)
	}
	// Mismatched lengths use the common prefix.
	r = Kappa([]string{"a", "b", "a"}, []string{"a", "b"})
	if r.N != 2 || !r.Defined {
		t.Errorf("length mismatch handling: %+v", r)
	}
}

func TestProportionAndMean(t *testing.T) {
	if _, ok := Proportion(1, 0); ok {
		t.Error("Proportion with n=0 must not be ok")
	}
	if p, ok := Proportion(1, 4); !ok || p != 0.25 {
		t.Errorf("Proportion(1,4) = %v ok=%v", p, ok)
	}
	if _, ok := Mean(nil); ok {
		t.Error("Mean of empty slice must not be ok")
	}
}
