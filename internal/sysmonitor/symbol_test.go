package sysmonitor

import (
	"debug/elf"
	"regexp"
	"testing"
)

// func TestFindOffset(t *testing.T) {
// 	{
// 		goBin := []string{}
// 		for i := 10; i <= 21; i++ {
// 			goBin = append(goBin, "gooffset/compile/nocgo/dist/"+"gobin.arm64.go1."+strconv.Itoa(i))
// 			goBin = append(goBin, "gooffset/compile/nocgo/dist/"+"gobin.amd64.go1."+strconv.Itoa(i))
// 		}
// 		for _, v := range goBin {
// 			t.Run(v, func(t *testing.T) {
// 				goVer := [2]int{}

// 				inf, err := buildinfo.ReadFile(v)
// 				if err != nil {
// 					// t.Error(err)
// 				} else {
// 					goVer, _ = parseGoVersion(inf.GoVersion)
// 				}

// 				s1, err := FindSymbol(v, regexp.MustCompile(`^runtime\.execute$`))
// 				if err != nil {
// 					t.Error(err)
// 				} else {
// 					t.Log(s1)
// 				}

// 				s2, err := getGoUprobeSymbolFromPCLN(v, goVer[1] >= 20, "runtime.execute")
// 				if err != nil {
// 					t.Error(err)
// 					return
// 				} else {
// 					t.Log(s2)
// 				}
// 				if len(s1) == 1 {
// 					assert.Equal(t, s1[0].Value, s2.Start)
// 					assert.Equal(t, s1[0].Name, s2.Name)
// 				} else {
// 					t.Error("func offset not eq")
// 				}

// 				offset, err := FindMemberOffsetFromFile(v, "runtime.g", "goid")
// 				if err != nil {
// 					t.Error(v, " ", err)
// 				}
// 				t.Log(offset)
// 				assert.Equal(t, int64(152), offset)
// 			})
// 		}
// 	}
// 	{
// 		goBin := []string{}
// 		for i := 10; i <= 21; i++ {
// 			goBin = append(goBin, "gooffset/compile/cgo/dist/"+"gobin.arm64.go1."+strconv.Itoa(i))
// 			goBin = append(goBin, "gooffset/compile/cgo/dist/"+"gobin.amd64.go1."+strconv.Itoa(i))
// 		}
// 		goVer := [2]int{}
// 		for _, v := range goBin {
// 			t.Run(v, func(t *testing.T) {
// 				inf, err := buildinfo.ReadFile(v)
// 				if err != nil {
// 					// t.Error(err)
// 				} else {
// 					goVer, _ = parseGoVersion(inf.GoVersion)
// 				}

// 				s1, err := FindSymbol(v, regexp.MustCompile(`^runtime\.execute$`))
// 				if err != nil {
// 					t.Error(err)
// 				} else {
// 					t.Log(s1)
// 				}

// 				s2, err := getGoUprobeSymbolFromPCLN(v, goVer[1] >= 20, "runtime.execute")
// 				if err != nil {
// 					t.Error(err)
// 					return
// 				} else {
// 					t.Log(s2)
// 				}
// 				if len(s1) == 1 {
// 					assert.Equal(t, s1[0].Value, s2.Start)
// 					assert.Equal(t, s1[0].Name, s2.Name)
// 				} else {
// 					t.Error("func offset not eq")
// 				}

// 				offset, err := FindMemberOffsetFromFile(v, "runtime.g", "goid")
// 				if err != nil {
// 					t.Error(v, " ", err)
// 				}

// 				assert.Equal(t, int64(152), offset)
// 			})
// 		}
// 	}
// }

func TestSym(t *testing.T) {
	fp := "/home/vircoys/go/src/github.com/GuanceCloud/datakit-ebpf/dist/amd64/datakit-ebpf"
	f, err := elf.Open(fp)
	if err != nil {
		t.Fatal(err)
	}
	s, err := FindDynamicSymbol(f, regexp.MustCompile("^pthread"))
	if err != nil {
		t.Fatal(err)
	}
	t.Error(s)

	s1, err := FindSymbol(f, regexp.MustCompile("a"))
	if err != nil {
		t.Fatal(err)
	}
	t.Error(s1)

}
