/*
Copyright 2016 The Kubernetes Authors.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

// ************************************************************
// DO NOT EDIT.
// THIS FILE IS AUTO-GENERATED BY codecgen.
// ************************************************************

package apps

import (
	"errors"
	"fmt"
	codec1978 "github.com/ugorji/go/codec"
	pkg2_api "k8s.io/client-go/1.4/pkg/api"
	pkg4_resource "k8s.io/client-go/1.4/pkg/api/resource"
	pkg1_unversioned "k8s.io/client-go/1.4/pkg/api/unversioned"
	pkg3_types "k8s.io/client-go/1.4/pkg/types"
	pkg5_intstr "k8s.io/client-go/1.4/pkg/util/intstr"
	"reflect"
	"runtime"
	time "time"
)

const (
	// ----- content types ----
	codecSelferC_UTF81234 = 1
	codecSelferC_RAW1234  = 0
	// ----- value types used ----
	codecSelferValueTypeArray1234 = 10
	codecSelferValueTypeMap1234   = 9
	// ----- containerStateValues ----
	codecSelfer_containerMapKey1234    = 2
	codecSelfer_containerMapValue1234  = 3
	codecSelfer_containerMapEnd1234    = 4
	codecSelfer_containerArrayElem1234 = 6
	codecSelfer_containerArrayEnd1234  = 7
)

var (
	codecSelferBitsize1234                         = uint8(reflect.TypeOf(uint(0)).Bits())
	codecSelferOnlyMapOrArrayEncodeToStructErr1234 = errors.New(`only encoded map or array can be decoded into a struct`)
)

type codecSelfer1234 struct{}

func init() {
	if codec1978.GenVersion != 5 {
		_, file, _, _ := runtime.Caller(0)
		err := fmt.Errorf("codecgen version mismatch: current: %v, need %v. Re-generate file: %v",
			5, codec1978.GenVersion, file)
		panic(err)
	}
	if false { // reference the types, but skip this branch at build/run time
		var v0 pkg2_api.ObjectMeta
		var v1 pkg4_resource.Quantity
		var v2 pkg1_unversioned.TypeMeta
		var v3 pkg3_types.UID
		var v4 pkg5_intstr.IntOrString
		var v5 time.Time
		_, _, _, _, _, _ = v0, v1, v2, v3, v4, v5
	}
}

func (x *PetSet) CodecEncodeSelf(e *codec1978.Encoder) {
	var h codecSelfer1234
	z, r := codec1978.GenHelperEncoder(e)
	_, _, _ = h, z, r
	if x == nil {
		r.EncodeNil()
	} else {
		yym1 := z.EncBinary()
		_ = yym1
		if false {
		} else if z.HasExtensions() && z.EncExt(x) {
		} else {
			yysep2 := !z.EncBinary()
			yy2arr2 := z.EncBasicHandle().StructToArray
			var yyq2 [5]bool
			_, _, _ = yysep2, yyq2, yy2arr2
			const yyr2 bool = false
			yyq2[0] = x.Kind != ""
			yyq2[1] = x.APIVersion != ""
			yyq2[2] = true
			yyq2[3] = true
			yyq2[4] = true
			var yynn2 int
			if yyr2 || yy2arr2 {
				r.EncodeArrayStart(5)
			} else {
				yynn2 = 0
				for _, b := range yyq2 {
					if b {
						yynn2++
					}
				}
				r.EncodeMapStart(yynn2)
				yynn2 = 0
			}
			if yyr2 || yy2arr2 {
				z.EncSendContainerState(codecSelfer_containerArrayElem1234)
				if yyq2[0] {
					yym4 := z.EncBinary()
					_ = yym4
					if false {
					} else {
						r.EncodeString(codecSelferC_UTF81234, string(x.Kind))
					}
				} else {
					r.EncodeString(codecSelferC_UTF81234, "")
				}
			} else {
				if yyq2[0] {
					z.EncSendContainerState(codecSelfer_containerMapKey1234)
					r.EncodeString(codecSelferC_UTF81234, string("kind"))
					z.EncSendContainerState(codecSelfer_containerMapValue1234)
					yym5 := z.EncBinary()
					_ = yym5
					if false {
					} else {
						r.EncodeString(codecSelferC_UTF81234, string(x.Kind))
					}
				}
			}
			if yyr2 || yy2arr2 {
				z.EncSendContainerState(codecSelfer_containerArrayElem1234)
				if yyq2[1] {
					yym7 := z.EncBinary()
					_ = yym7
					if false {
					} else {
						r.EncodeString(codecSelferC_UTF81234, string(x.APIVersion))
					}
				} else {
					r.EncodeString(codecSelferC_UTF81234, "")
				}
			} else {
				if yyq2[1] {
					z.EncSendContainerState(codecSelfer_containerMapKey1234)
					r.EncodeString(codecSelferC_UTF81234, string("apiVersion"))
					z.EncSendContainerState(codecSelfer_containerMapValue1234)
					yym8 := z.EncBinary()
					_ = yym8
					if false {
					} else {
						r.EncodeString(codecSelferC_UTF81234, string(x.APIVersion))
					}
				}
			}
			if yyr2 || yy2arr2 {
				z.EncSendContainerState(codecSelfer_containerArrayElem1234)
				if yyq2[2] {
					yy10 := &x.ObjectMeta
					yy10.CodecEncodeSelf(e)
				} else {
					r.EncodeNil()
				}
			} else {
				if yyq2[2] {
					z.EncSendContainerState(codecSelfer_containerMapKey1234)
					r.EncodeString(codecSelferC_UTF81234, string("metadata"))
					z.EncSendContainerState(codecSelfer_containerMapValue1234)
					yy11 := &x.ObjectMeta
					yy11.CodecEncodeSelf(e)
				}
			}
			if yyr2 || yy2arr2 {
				z.EncSendContainerState(codecSelfer_containerArrayElem1234)
				if yyq2[3] {
					yy13 := &x.Spec
					yy13.CodecEncodeSelf(e)
				} else {
					r.EncodeNil()
				}
			} else {
				if yyq2[3] {
					z.EncSendContainerState(codecSelfer_containerMapKey1234)
					r.EncodeString(codecSelferC_UTF81234, string("spec"))
					z.EncSendContainerState(codecSelfer_containerMapValue1234)
					yy14 := &x.Spec
					yy14.CodecEncodeSelf(e)
				}
			}
			if yyr2 || yy2arr2 {
				z.EncSendContainerState(codecSelfer_containerArrayElem1234)
				if yyq2[4] {
					yy16 := &x.Status
					yy16.CodecEncodeSelf(e)
				} else {
					r.EncodeNil()
				}
			} else {
				if yyq2[4] {
					z.EncSendContainerState(codecSelfer_containerMapKey1234)
					r.EncodeString(codecSelferC_UTF81234, string("status"))
					z.EncSendContainerState(codecSelfer_containerMapValue1234)
					yy17 := &x.Status
					yy17.CodecEncodeSelf(e)
				}
			}
			if yyr2 || yy2arr2 {
				z.EncSendContainerState(codecSelfer_containerArrayEnd1234)
			} else {
				z.EncSendContainerState(codecSelfer_containerMapEnd1234)
			}
		}
	}
}

func (x *PetSet) CodecDecodeSelf(d *codec1978.Decoder) {
	var h codecSelfer1234
	z, r := codec1978.GenHelperDecoder(d)
	_, _, _ = h, z, r
	yym18 := z.DecBinary()
	_ = yym18
	if false {
	} else if z.HasExtensions() && z.DecExt(x) {
	} else {
		yyct19 := r.ContainerType()
		if yyct19 == codecSelferValueTypeMap1234 {
			yyl19 := r.ReadMapStart()
			if yyl19 == 0 {
				z.DecSendContainerState(codecSelfer_containerMapEnd1234)
			} else {
				x.codecDecodeSelfFromMap(yyl19, d)
			}
		} else if yyct19 == codecSelferValueTypeArray1234 {
			yyl19 := r.ReadArrayStart()
			if yyl19 == 0 {
				z.DecSendContainerState(codecSelfer_containerArrayEnd1234)
			} else {
				x.codecDecodeSelfFromArray(yyl19, d)
			}
		} else {
			panic(codecSelferOnlyMapOrArrayEncodeToStructErr1234)
		}
	}
}

func (x *PetSet) codecDecodeSelfFromMap(l int, d *codec1978.Decoder) {
	var h codecSelfer1234
	z, r := codec1978.GenHelperDecoder(d)
	_, _, _ = h, z, r
	var yys20Slc = z.DecScratchBuffer() // default slice to decode into
	_ = yys20Slc
	var yyhl20 bool = l >= 0
	for yyj20 := 0; ; yyj20++ {
		if yyhl20 {
			if yyj20 >= l {
				break
			}
		} else {
			if r.CheckBreak() {
				break
			}
		}
		z.DecSendContainerState(codecSelfer_containerMapKey1234)
		yys20Slc = r.DecodeBytes(yys20Slc, true, true)
		yys20 := string(yys20Slc)
		z.DecSendContainerState(codecSelfer_containerMapValue1234)
		switch yys20 {
		case "kind":
			if r.TryDecodeAsNil() {
				x.Kind = ""
			} else {
				x.Kind = string(r.DecodeString())
			}
		case "apiVersion":
			if r.TryDecodeAsNil() {
				x.APIVersion = ""
			} else {
				x.APIVersion = string(r.DecodeString())
			}
		case "metadata":
			if r.TryDecodeAsNil() {
				x.ObjectMeta = pkg2_api.ObjectMeta{}
			} else {
				yyv23 := &x.ObjectMeta
				yyv23.CodecDecodeSelf(d)
			}
		case "spec":
			if r.TryDecodeAsNil() {
				x.Spec = PetSetSpec{}
			} else {
				yyv24 := &x.Spec
				yyv24.CodecDecodeSelf(d)
			}
		case "status":
			if r.TryDecodeAsNil() {
				x.Status = PetSetStatus{}
			} else {
				yyv25 := &x.Status
				yyv25.CodecDecodeSelf(d)
			}
		default:
			z.DecStructFieldNotFound(-1, yys20)
		} // end switch yys20
	} // end for yyj20
	z.DecSendContainerState(codecSelfer_containerMapEnd1234)
}

func (x *PetSet) codecDecodeSelfFromArray(l int, d *codec1978.Decoder) {
	var h codecSelfer1234
	z, r := codec1978.GenHelperDecoder(d)
	_, _, _ = h, z, r
	var yyj26 int
	var yyb26 bool
	var yyhl26 bool = l >= 0
	yyj26++
	if yyhl26 {
		yyb26 = yyj26 > l
	} else {
		yyb26 = r.CheckBreak()
	}
	if yyb26 {
		z.DecSendContainerState(codecSelfer_containerArrayEnd1234)
		return
	}
	z.DecSendContainerState(codecSelfer_containerArrayElem1234)
	if r.TryDecodeAsNil() {
		x.Kind = ""
	} else {
		x.Kind = string(r.DecodeString())
	}
	yyj26++
	if yyhl26 {
		yyb26 = yyj26 > l
	} else {
		yyb26 = r.CheckBreak()
	}
	if yyb26 {
		z.DecSendContainerState(codecSelfer_containerArrayEnd1234)
		return
	}
	z.DecSendContainerState(codecSelfer_containerArrayElem1234)
	if r.TryDecodeAsNil() {
		x.APIVersion = ""
	} else {
		x.APIVersion = string(r.DecodeString())
	}
	yyj26++
	if yyhl26 {
		yyb26 = yyj26 > l
	} else {
		yyb26 = r.CheckBreak()
	}
	if yyb26 {
		z.DecSendContainerState(codecSelfer_containerArrayEnd1234)
		return
	}
	z.DecSendContainerState(codecSelfer_containerArrayElem1234)
	if r.TryDecodeAsNil() {
		x.ObjectMeta = pkg2_api.ObjectMeta{}
	} else {
		yyv29 := &x.ObjectMeta
		yyv29.CodecDecodeSelf(d)
	}
	yyj26++
	if yyhl26 {
		yyb26 = yyj26 > l
	} else {
		yyb26 = r.CheckBreak()
	}
	if yyb26 {
		z.DecSendContainerState(codecSelfer_containerArrayEnd1234)
		return
	}
	z.DecSendContainerState(codecSelfer_containerArrayElem1234)
	if r.TryDecodeAsNil() {
		x.Spec = PetSetSpec{}
	} else {
		yyv30 := &x.Spec
		yyv30.CodecDecodeSelf(d)
	}
	yyj26++
	if yyhl26 {
		yyb26 = yyj26 > l
	} else {
		yyb26 = r.CheckBreak()
	}
	if yyb26 {
		z.DecSendContainerState(codecSelfer_containerArrayEnd1234)
		return
	}
	z.DecSendContainerState(codecSelfer_containerArrayElem1234)
	if r.TryDecodeAsNil() {
		x.Status = PetSetStatus{}
	} else {
		yyv31 := &x.Status
		yyv31.CodecDecodeSelf(d)
	}
	for {
		yyj26++
		if yyhl26 {
			yyb26 = yyj26 > l
		} else {
			yyb26 = r.CheckBreak()
		}
		if yyb26 {
			break
		}
		z.DecSendContainerState(codecSelfer_containerArrayElem1234)
		z.DecStructFieldNotFound(yyj26-1, "")
	}
	z.DecSendContainerState(codecSelfer_containerArrayEnd1234)
}

func (x *PetSetSpec) CodecEncodeSelf(e *codec1978.Encoder) {
	var h codecSelfer1234
	z, r := codec1978.GenHelperEncoder(e)
	_, _, _ = h, z, r
	if x == nil {
		r.EncodeNil()
	} else {
		yym32 := z.EncBinary()
		_ = yym32
		if false {
		} else if z.HasExtensions() && z.EncExt(x) {
		} else {
			yysep33 := !z.EncBinary()
			yy2arr33 := z.EncBasicHandle().StructToArray
			var yyq33 [5]bool
			_, _, _ = yysep33, yyq33, yy2arr33
			const yyr33 bool = false
			yyq33[0] = x.Replicas != 0
			yyq33[1] = x.Selector != nil
			yyq33[3] = len(x.VolumeClaimTemplates) != 0
			var yynn33 int
			if yyr33 || yy2arr33 {
				r.EncodeArrayStart(5)
			} else {
				yynn33 = 2
				for _, b := range yyq33 {
					if b {
						yynn33++
					}
				}
				r.EncodeMapStart(yynn33)
				yynn33 = 0
			}
			if yyr33 || yy2arr33 {
				z.EncSendContainerState(codecSelfer_containerArrayElem1234)
				if yyq33[0] {
					yym35 := z.EncBinary()
					_ = yym35
					if false {
					} else {
						r.EncodeInt(int64(x.Replicas))
					}
				} else {
					r.EncodeInt(0)
				}
			} else {
				if yyq33[0] {
					z.EncSendContainerState(codecSelfer_containerMapKey1234)
					r.EncodeString(codecSelferC_UTF81234, string("replicas"))
					z.EncSendContainerState(codecSelfer_containerMapValue1234)
					yym36 := z.EncBinary()
					_ = yym36
					if false {
					} else {
						r.EncodeInt(int64(x.Replicas))
					}
				}
			}
			if yyr33 || yy2arr33 {
				z.EncSendContainerState(codecSelfer_containerArrayElem1234)
				if yyq33[1] {
					if x.Selector == nil {
						r.EncodeNil()
					} else {
						yym38 := z.EncBinary()
						_ = yym38
						if false {
						} else if z.HasExtensions() && z.EncExt(x.Selector) {
						} else {
							z.EncFallback(x.Selector)
						}
					}
				} else {
					r.EncodeNil()
				}
			} else {
				if yyq33[1] {
					z.EncSendContainerState(codecSelfer_containerMapKey1234)
					r.EncodeString(codecSelferC_UTF81234, string("selector"))
					z.EncSendContainerState(codecSelfer_containerMapValue1234)
					if x.Selector == nil {
						r.EncodeNil()
					} else {
						yym39 := z.EncBinary()
						_ = yym39
						if false {
						} else if z.HasExtensions() && z.EncExt(x.Selector) {
						} else {
							z.EncFallback(x.Selector)
						}
					}
				}
			}
			if yyr33 || yy2arr33 {
				z.EncSendContainerState(codecSelfer_containerArrayElem1234)
				yy41 := &x.Template
				yy41.CodecEncodeSelf(e)
			} else {
				z.EncSendContainerState(codecSelfer_containerMapKey1234)
				r.EncodeString(codecSelferC_UTF81234, string("template"))
				z.EncSendContainerState(codecSelfer_containerMapValue1234)
				yy42 := &x.Template
				yy42.CodecEncodeSelf(e)
			}
			if yyr33 || yy2arr33 {
				z.EncSendContainerState(codecSelfer_containerArrayElem1234)
				if yyq33[3] {
					if x.VolumeClaimTemplates == nil {
						r.EncodeNil()
					} else {
						yym44 := z.EncBinary()
						_ = yym44
						if false {
						} else {
							h.encSliceapi_PersistentVolumeClaim(([]pkg2_api.PersistentVolumeClaim)(x.VolumeClaimTemplates), e)
						}
					}
				} else {
					r.EncodeNil()
				}
			} else {
				if yyq33[3] {
					z.EncSendContainerState(codecSelfer_containerMapKey1234)
					r.EncodeString(codecSelferC_UTF81234, string("volumeClaimTemplates"))
					z.EncSendContainerState(codecSelfer_containerMapValue1234)
					if x.VolumeClaimTemplates == nil {
						r.EncodeNil()
					} else {
						yym45 := z.EncBinary()
						_ = yym45
						if false {
						} else {
							h.encSliceapi_PersistentVolumeClaim(([]pkg2_api.PersistentVolumeClaim)(x.VolumeClaimTemplates), e)
						}
					}
				}
			}
			if yyr33 || yy2arr33 {
				z.EncSendContainerState(codecSelfer_containerArrayElem1234)
				yym47 := z.EncBinary()
				_ = yym47
				if false {
				} else {
					r.EncodeString(codecSelferC_UTF81234, string(x.ServiceName))
				}
			} else {
				z.EncSendContainerState(codecSelfer_containerMapKey1234)
				r.EncodeString(codecSelferC_UTF81234, string("serviceName"))
				z.EncSendContainerState(codecSelfer_containerMapValue1234)
				yym48 := z.EncBinary()
				_ = yym48
				if false {
				} else {
					r.EncodeString(codecSelferC_UTF81234, string(x.ServiceName))
				}
			}
			if yyr33 || yy2arr33 {
				z.EncSendContainerState(codecSelfer_containerArrayEnd1234)
			} else {
				z.EncSendContainerState(codecSelfer_containerMapEnd1234)
			}
		}
	}
}

func (x *PetSetSpec) CodecDecodeSelf(d *codec1978.Decoder) {
	var h codecSelfer1234
	z, r := codec1978.GenHelperDecoder(d)
	_, _, _ = h, z, r
	yym49 := z.DecBinary()
	_ = yym49
	if false {
	} else if z.HasExtensions() && z.DecExt(x) {
	} else {
		yyct50 := r.ContainerType()
		if yyct50 == codecSelferValueTypeMap1234 {
			yyl50 := r.ReadMapStart()
			if yyl50 == 0 {
				z.DecSendContainerState(codecSelfer_containerMapEnd1234)
			} else {
				x.codecDecodeSelfFromMap(yyl50, d)
			}
		} else if yyct50 == codecSelferValueTypeArray1234 {
			yyl50 := r.ReadArrayStart()
			if yyl50 == 0 {
				z.DecSendContainerState(codecSelfer_containerArrayEnd1234)
			} else {
				x.codecDecodeSelfFromArray(yyl50, d)
			}
		} else {
			panic(codecSelferOnlyMapOrArrayEncodeToStructErr1234)
		}
	}
}

func (x *PetSetSpec) codecDecodeSelfFromMap(l int, d *codec1978.Decoder) {
	var h codecSelfer1234
	z, r := codec1978.GenHelperDecoder(d)
	_, _, _ = h, z, r
	var yys51Slc = z.DecScratchBuffer() // default slice to decode into
	_ = yys51Slc
	var yyhl51 bool = l >= 0
	for yyj51 := 0; ; yyj51++ {
		if yyhl51 {
			if yyj51 >= l {
				break
			}
		} else {
			if r.CheckBreak() {
				break
			}
		}
		z.DecSendContainerState(codecSelfer_containerMapKey1234)
		yys51Slc = r.DecodeBytes(yys51Slc, true, true)
		yys51 := string(yys51Slc)
		z.DecSendContainerState(codecSelfer_containerMapValue1234)
		switch yys51 {
		case "replicas":
			if r.TryDecodeAsNil() {
				x.Replicas = 0
			} else {
				x.Replicas = int(r.DecodeInt(codecSelferBitsize1234))
			}
		case "selector":
			if r.TryDecodeAsNil() {
				if x.Selector != nil {
					x.Selector = nil
				}
			} else {
				if x.Selector == nil {
					x.Selector = new(pkg1_unversioned.LabelSelector)
				}
				yym54 := z.DecBinary()
				_ = yym54
				if false {
				} else if z.HasExtensions() && z.DecExt(x.Selector) {
				} else {
					z.DecFallback(x.Selector, false)
				}
			}
		case "template":
			if r.TryDecodeAsNil() {
				x.Template = pkg2_api.PodTemplateSpec{}
			} else {
				yyv55 := &x.Template
				yyv55.CodecDecodeSelf(d)
			}
		case "volumeClaimTemplates":
			if r.TryDecodeAsNil() {
				x.VolumeClaimTemplates = nil
			} else {
				yyv56 := &x.VolumeClaimTemplates
				yym57 := z.DecBinary()
				_ = yym57
				if false {
				} else {
					h.decSliceapi_PersistentVolumeClaim((*[]pkg2_api.PersistentVolumeClaim)(yyv56), d)
				}
			}
		case "serviceName":
			if r.TryDecodeAsNil() {
				x.ServiceName = ""
			} else {
				x.ServiceName = string(r.DecodeString())
			}
		default:
			z.DecStructFieldNotFound(-1, yys51)
		} // end switch yys51
	} // end for yyj51
	z.DecSendContainerState(codecSelfer_containerMapEnd1234)
}

func (x *PetSetSpec) codecDecodeSelfFromArray(l int, d *codec1978.Decoder) {
	var h codecSelfer1234
	z, r := codec1978.GenHelperDecoder(d)
	_, _, _ = h, z, r
	var yyj59 int
	var yyb59 bool
	var yyhl59 bool = l >= 0
	yyj59++
	if yyhl59 {
		yyb59 = yyj59 > l
	} else {
		yyb59 = r.CheckBreak()
	}
	if yyb59 {
		z.DecSendContainerState(codecSelfer_containerArrayEnd1234)
		return
	}
	z.DecSendContainerState(codecSelfer_containerArrayElem1234)
	if r.TryDecodeAsNil() {
		x.Replicas = 0
	} else {
		x.Replicas = int(r.DecodeInt(codecSelferBitsize1234))
	}
	yyj59++
	if yyhl59 {
		yyb59 = yyj59 > l
	} else {
		yyb59 = r.CheckBreak()
	}
	if yyb59 {
		z.DecSendContainerState(codecSelfer_containerArrayEnd1234)
		return
	}
	z.DecSendContainerState(codecSelfer_containerArrayElem1234)
	if r.TryDecodeAsNil() {
		if x.Selector != nil {
			x.Selector = nil
		}
	} else {
		if x.Selector == nil {
			x.Selector = new(pkg1_unversioned.LabelSelector)
		}
		yym62 := z.DecBinary()
		_ = yym62
		if false {
		} else if z.HasExtensions() && z.DecExt(x.Selector) {
		} else {
			z.DecFallback(x.Selector, false)
		}
	}
	yyj59++
	if yyhl59 {
		yyb59 = yyj59 > l
	} else {
		yyb59 = r.CheckBreak()
	}
	if yyb59 {
		z.DecSendContainerState(codecSelfer_containerArrayEnd1234)
		return
	}
	z.DecSendContainerState(codecSelfer_containerArrayElem1234)
	if r.TryDecodeAsNil() {
		x.Template = pkg2_api.PodTemplateSpec{}
	} else {
		yyv63 := &x.Template
		yyv63.CodecDecodeSelf(d)
	}
	yyj59++
	if yyhl59 {
		yyb59 = yyj59 > l
	} else {
		yyb59 = r.CheckBreak()
	}
	if yyb59 {
		z.DecSendContainerState(codecSelfer_containerArrayEnd1234)
		return
	}
	z.DecSendContainerState(codecSelfer_containerArrayElem1234)
	if r.TryDecodeAsNil() {
		x.VolumeClaimTemplates = nil
	} else {
		yyv64 := &x.VolumeClaimTemplates
		yym65 := z.DecBinary()
		_ = yym65
		if false {
		} else {
			h.decSliceapi_PersistentVolumeClaim((*[]pkg2_api.PersistentVolumeClaim)(yyv64), d)
		}
	}
	yyj59++
	if yyhl59 {
		yyb59 = yyj59 > l
	} else {
		yyb59 = r.CheckBreak()
	}
	if yyb59 {
		z.DecSendContainerState(codecSelfer_containerArrayEnd1234)
		return
	}
	z.DecSendContainerState(codecSelfer_containerArrayElem1234)
	if r.TryDecodeAsNil() {
		x.ServiceName = ""
	} else {
		x.ServiceName = string(r.DecodeString())
	}
	for {
		yyj59++
		if yyhl59 {
			yyb59 = yyj59 > l
		} else {
			yyb59 = r.CheckBreak()
		}
		if yyb59 {
			break
		}
		z.DecSendContainerState(codecSelfer_containerArrayElem1234)
		z.DecStructFieldNotFound(yyj59-1, "")
	}
	z.DecSendContainerState(codecSelfer_containerArrayEnd1234)
}

func (x *PetSetStatus) CodecEncodeSelf(e *codec1978.Encoder) {
	var h codecSelfer1234
	z, r := codec1978.GenHelperEncoder(e)
	_, _, _ = h, z, r
	if x == nil {
		r.EncodeNil()
	} else {
		yym67 := z.EncBinary()
		_ = yym67
		if false {
		} else if z.HasExtensions() && z.EncExt(x) {
		} else {
			yysep68 := !z.EncBinary()
			yy2arr68 := z.EncBasicHandle().StructToArray
			var yyq68 [2]bool
			_, _, _ = yysep68, yyq68, yy2arr68
			const yyr68 bool = false
			yyq68[0] = x.ObservedGeneration != nil
			var yynn68 int
			if yyr68 || yy2arr68 {
				r.EncodeArrayStart(2)
			} else {
				yynn68 = 1
				for _, b := range yyq68 {
					if b {
						yynn68++
					}
				}
				r.EncodeMapStart(yynn68)
				yynn68 = 0
			}
			if yyr68 || yy2arr68 {
				z.EncSendContainerState(codecSelfer_containerArrayElem1234)
				if yyq68[0] {
					if x.ObservedGeneration == nil {
						r.EncodeNil()
					} else {
						yy70 := *x.ObservedGeneration
						yym71 := z.EncBinary()
						_ = yym71
						if false {
						} else {
							r.EncodeInt(int64(yy70))
						}
					}
				} else {
					r.EncodeNil()
				}
			} else {
				if yyq68[0] {
					z.EncSendContainerState(codecSelfer_containerMapKey1234)
					r.EncodeString(codecSelferC_UTF81234, string("observedGeneration"))
					z.EncSendContainerState(codecSelfer_containerMapValue1234)
					if x.ObservedGeneration == nil {
						r.EncodeNil()
					} else {
						yy72 := *x.ObservedGeneration
						yym73 := z.EncBinary()
						_ = yym73
						if false {
						} else {
							r.EncodeInt(int64(yy72))
						}
					}
				}
			}
			if yyr68 || yy2arr68 {
				z.EncSendContainerState(codecSelfer_containerArrayElem1234)
				yym75 := z.EncBinary()
				_ = yym75
				if false {
				} else {
					r.EncodeInt(int64(x.Replicas))
				}
			} else {
				z.EncSendContainerState(codecSelfer_containerMapKey1234)
				r.EncodeString(codecSelferC_UTF81234, string("replicas"))
				z.EncSendContainerState(codecSelfer_containerMapValue1234)
				yym76 := z.EncBinary()
				_ = yym76
				if false {
				} else {
					r.EncodeInt(int64(x.Replicas))
				}
			}
			if yyr68 || yy2arr68 {
				z.EncSendContainerState(codecSelfer_containerArrayEnd1234)
			} else {
				z.EncSendContainerState(codecSelfer_containerMapEnd1234)
			}
		}
	}
}

func (x *PetSetStatus) CodecDecodeSelf(d *codec1978.Decoder) {
	var h codecSelfer1234
	z, r := codec1978.GenHelperDecoder(d)
	_, _, _ = h, z, r
	yym77 := z.DecBinary()
	_ = yym77
	if false {
	} else if z.HasExtensions() && z.DecExt(x) {
	} else {
		yyct78 := r.ContainerType()
		if yyct78 == codecSelferValueTypeMap1234 {
			yyl78 := r.ReadMapStart()
			if yyl78 == 0 {
				z.DecSendContainerState(codecSelfer_containerMapEnd1234)
			} else {
				x.codecDecodeSelfFromMap(yyl78, d)
			}
		} else if yyct78 == codecSelferValueTypeArray1234 {
			yyl78 := r.ReadArrayStart()
			if yyl78 == 0 {
				z.DecSendContainerState(codecSelfer_containerArrayEnd1234)
			} else {
				x.codecDecodeSelfFromArray(yyl78, d)
			}
		} else {
			panic(codecSelferOnlyMapOrArrayEncodeToStructErr1234)
		}
	}
}

func (x *PetSetStatus) codecDecodeSelfFromMap(l int, d *codec1978.Decoder) {
	var h codecSelfer1234
	z, r := codec1978.GenHelperDecoder(d)
	_, _, _ = h, z, r
	var yys79Slc = z.DecScratchBuffer() // default slice to decode into
	_ = yys79Slc
	var yyhl79 bool = l >= 0
	for yyj79 := 0; ; yyj79++ {
		if yyhl79 {
			if yyj79 >= l {
				break
			}
		} else {
			if r.CheckBreak() {
				break
			}
		}
		z.DecSendContainerState(codecSelfer_containerMapKey1234)
		yys79Slc = r.DecodeBytes(yys79Slc, true, true)
		yys79 := string(yys79Slc)
		z.DecSendContainerState(codecSelfer_containerMapValue1234)
		switch yys79 {
		case "observedGeneration":
			if r.TryDecodeAsNil() {
				if x.ObservedGeneration != nil {
					x.ObservedGeneration = nil
				}
			} else {
				if x.ObservedGeneration == nil {
					x.ObservedGeneration = new(int64)
				}
				yym81 := z.DecBinary()
				_ = yym81
				if false {
				} else {
					*((*int64)(x.ObservedGeneration)) = int64(r.DecodeInt(64))
				}
			}
		case "replicas":
			if r.TryDecodeAsNil() {
				x.Replicas = 0
			} else {
				x.Replicas = int(r.DecodeInt(codecSelferBitsize1234))
			}
		default:
			z.DecStructFieldNotFound(-1, yys79)
		} // end switch yys79
	} // end for yyj79
	z.DecSendContainerState(codecSelfer_containerMapEnd1234)
}

func (x *PetSetStatus) codecDecodeSelfFromArray(l int, d *codec1978.Decoder) {
	var h codecSelfer1234
	z, r := codec1978.GenHelperDecoder(d)
	_, _, _ = h, z, r
	var yyj83 int
	var yyb83 bool
	var yyhl83 bool = l >= 0
	yyj83++
	if yyhl83 {
		yyb83 = yyj83 > l
	} else {
		yyb83 = r.CheckBreak()
	}
	if yyb83 {
		z.DecSendContainerState(codecSelfer_containerArrayEnd1234)
		return
	}
	z.DecSendContainerState(codecSelfer_containerArrayElem1234)
	if r.TryDecodeAsNil() {
		if x.ObservedGeneration != nil {
			x.ObservedGeneration = nil
		}
	} else {
		if x.ObservedGeneration == nil {
			x.ObservedGeneration = new(int64)
		}
		yym85 := z.DecBinary()
		_ = yym85
		if false {
		} else {
			*((*int64)(x.ObservedGeneration)) = int64(r.DecodeInt(64))
		}
	}
	yyj83++
	if yyhl83 {
		yyb83 = yyj83 > l
	} else {
		yyb83 = r.CheckBreak()
	}
	if yyb83 {
		z.DecSendContainerState(codecSelfer_containerArrayEnd1234)
		return
	}
	z.DecSendContainerState(codecSelfer_containerArrayElem1234)
	if r.TryDecodeAsNil() {
		x.Replicas = 0
	} else {
		x.Replicas = int(r.DecodeInt(codecSelferBitsize1234))
	}
	for {
		yyj83++
		if yyhl83 {
			yyb83 = yyj83 > l
		} else {
			yyb83 = r.CheckBreak()
		}
		if yyb83 {
			break
		}
		z.DecSendContainerState(codecSelfer_containerArrayElem1234)
		z.DecStructFieldNotFound(yyj83-1, "")
	}
	z.DecSendContainerState(codecSelfer_containerArrayEnd1234)
}

func (x *PetSetList) CodecEncodeSelf(e *codec1978.Encoder) {
	var h codecSelfer1234
	z, r := codec1978.GenHelperEncoder(e)
	_, _, _ = h, z, r
	if x == nil {
		r.EncodeNil()
	} else {
		yym87 := z.EncBinary()
		_ = yym87
		if false {
		} else if z.HasExtensions() && z.EncExt(x) {
		} else {
			yysep88 := !z.EncBinary()
			yy2arr88 := z.EncBasicHandle().StructToArray
			var yyq88 [4]bool
			_, _, _ = yysep88, yyq88, yy2arr88
			const yyr88 bool = false
			yyq88[0] = x.Kind != ""
			yyq88[1] = x.APIVersion != ""
			yyq88[2] = true
			var yynn88 int
			if yyr88 || yy2arr88 {
				r.EncodeArrayStart(4)
			} else {
				yynn88 = 1
				for _, b := range yyq88 {
					if b {
						yynn88++
					}
				}
				r.EncodeMapStart(yynn88)
				yynn88 = 0
			}
			if yyr88 || yy2arr88 {
				z.EncSendContainerState(codecSelfer_containerArrayElem1234)
				if yyq88[0] {
					yym90 := z.EncBinary()
					_ = yym90
					if false {
					} else {
						r.EncodeString(codecSelferC_UTF81234, string(x.Kind))
					}
				} else {
					r.EncodeString(codecSelferC_UTF81234, "")
				}
			} else {
				if yyq88[0] {
					z.EncSendContainerState(codecSelfer_containerMapKey1234)
					r.EncodeString(codecSelferC_UTF81234, string("kind"))
					z.EncSendContainerState(codecSelfer_containerMapValue1234)
					yym91 := z.EncBinary()
					_ = yym91
					if false {
					} else {
						r.EncodeString(codecSelferC_UTF81234, string(x.Kind))
					}
				}
			}
			if yyr88 || yy2arr88 {
				z.EncSendContainerState(codecSelfer_containerArrayElem1234)
				if yyq88[1] {
					yym93 := z.EncBinary()
					_ = yym93
					if false {
					} else {
						r.EncodeString(codecSelferC_UTF81234, string(x.APIVersion))
					}
				} else {
					r.EncodeString(codecSelferC_UTF81234, "")
				}
			} else {
				if yyq88[1] {
					z.EncSendContainerState(codecSelfer_containerMapKey1234)
					r.EncodeString(codecSelferC_UTF81234, string("apiVersion"))
					z.EncSendContainerState(codecSelfer_containerMapValue1234)
					yym94 := z.EncBinary()
					_ = yym94
					if false {
					} else {
						r.EncodeString(codecSelferC_UTF81234, string(x.APIVersion))
					}
				}
			}
			if yyr88 || yy2arr88 {
				z.EncSendContainerState(codecSelfer_containerArrayElem1234)
				if yyq88[2] {
					yy96 := &x.ListMeta
					yym97 := z.EncBinary()
					_ = yym97
					if false {
					} else if z.HasExtensions() && z.EncExt(yy96) {
					} else {
						z.EncFallback(yy96)
					}
				} else {
					r.EncodeNil()
				}
			} else {
				if yyq88[2] {
					z.EncSendContainerState(codecSelfer_containerMapKey1234)
					r.EncodeString(codecSelferC_UTF81234, string("metadata"))
					z.EncSendContainerState(codecSelfer_containerMapValue1234)
					yy98 := &x.ListMeta
					yym99 := z.EncBinary()
					_ = yym99
					if false {
					} else if z.HasExtensions() && z.EncExt(yy98) {
					} else {
						z.EncFallback(yy98)
					}
				}
			}
			if yyr88 || yy2arr88 {
				z.EncSendContainerState(codecSelfer_containerArrayElem1234)
				if x.Items == nil {
					r.EncodeNil()
				} else {
					yym101 := z.EncBinary()
					_ = yym101
					if false {
					} else {
						h.encSlicePetSet(([]PetSet)(x.Items), e)
					}
				}
			} else {
				z.EncSendContainerState(codecSelfer_containerMapKey1234)
				r.EncodeString(codecSelferC_UTF81234, string("items"))
				z.EncSendContainerState(codecSelfer_containerMapValue1234)
				if x.Items == nil {
					r.EncodeNil()
				} else {
					yym102 := z.EncBinary()
					_ = yym102
					if false {
					} else {
						h.encSlicePetSet(([]PetSet)(x.Items), e)
					}
				}
			}
			if yyr88 || yy2arr88 {
				z.EncSendContainerState(codecSelfer_containerArrayEnd1234)
			} else {
				z.EncSendContainerState(codecSelfer_containerMapEnd1234)
			}
		}
	}
}

func (x *PetSetList) CodecDecodeSelf(d *codec1978.Decoder) {
	var h codecSelfer1234
	z, r := codec1978.GenHelperDecoder(d)
	_, _, _ = h, z, r
	yym103 := z.DecBinary()
	_ = yym103
	if false {
	} else if z.HasExtensions() && z.DecExt(x) {
	} else {
		yyct104 := r.ContainerType()
		if yyct104 == codecSelferValueTypeMap1234 {
			yyl104 := r.ReadMapStart()
			if yyl104 == 0 {
				z.DecSendContainerState(codecSelfer_containerMapEnd1234)
			} else {
				x.codecDecodeSelfFromMap(yyl104, d)
			}
		} else if yyct104 == codecSelferValueTypeArray1234 {
			yyl104 := r.ReadArrayStart()
			if yyl104 == 0 {
				z.DecSendContainerState(codecSelfer_containerArrayEnd1234)
			} else {
				x.codecDecodeSelfFromArray(yyl104, d)
			}
		} else {
			panic(codecSelferOnlyMapOrArrayEncodeToStructErr1234)
		}
	}
}

func (x *PetSetList) codecDecodeSelfFromMap(l int, d *codec1978.Decoder) {
	var h codecSelfer1234
	z, r := codec1978.GenHelperDecoder(d)
	_, _, _ = h, z, r
	var yys105Slc = z.DecScratchBuffer() // default slice to decode into
	_ = yys105Slc
	var yyhl105 bool = l >= 0
	for yyj105 := 0; ; yyj105++ {
		if yyhl105 {
			if yyj105 >= l {
				break
			}
		} else {
			if r.CheckBreak() {
				break
			}
		}
		z.DecSendContainerState(codecSelfer_containerMapKey1234)
		yys105Slc = r.DecodeBytes(yys105Slc, true, true)
		yys105 := string(yys105Slc)
		z.DecSendContainerState(codecSelfer_containerMapValue1234)
		switch yys105 {
		case "kind":
			if r.TryDecodeAsNil() {
				x.Kind = ""
			} else {
				x.Kind = string(r.DecodeString())
			}
		case "apiVersion":
			if r.TryDecodeAsNil() {
				x.APIVersion = ""
			} else {
				x.APIVersion = string(r.DecodeString())
			}
		case "metadata":
			if r.TryDecodeAsNil() {
				x.ListMeta = pkg1_unversioned.ListMeta{}
			} else {
				yyv108 := &x.ListMeta
				yym109 := z.DecBinary()
				_ = yym109
				if false {
				} else if z.HasExtensions() && z.DecExt(yyv108) {
				} else {
					z.DecFallback(yyv108, false)
				}
			}
		case "items":
			if r.TryDecodeAsNil() {
				x.Items = nil
			} else {
				yyv110 := &x.Items
				yym111 := z.DecBinary()
				_ = yym111
				if false {
				} else {
					h.decSlicePetSet((*[]PetSet)(yyv110), d)
				}
			}
		default:
			z.DecStructFieldNotFound(-1, yys105)
		} // end switch yys105
	} // end for yyj105
	z.DecSendContainerState(codecSelfer_containerMapEnd1234)
}

func (x *PetSetList) codecDecodeSelfFromArray(l int, d *codec1978.Decoder) {
	var h codecSelfer1234
	z, r := codec1978.GenHelperDecoder(d)
	_, _, _ = h, z, r
	var yyj112 int
	var yyb112 bool
	var yyhl112 bool = l >= 0
	yyj112++
	if yyhl112 {
		yyb112 = yyj112 > l
	} else {
		yyb112 = r.CheckBreak()
	}
	if yyb112 {
		z.DecSendContainerState(codecSelfer_containerArrayEnd1234)
		return
	}
	z.DecSendContainerState(codecSelfer_containerArrayElem1234)
	if r.TryDecodeAsNil() {
		x.Kind = ""
	} else {
		x.Kind = string(r.DecodeString())
	}
	yyj112++
	if yyhl112 {
		yyb112 = yyj112 > l
	} else {
		yyb112 = r.CheckBreak()
	}
	if yyb112 {
		z.DecSendContainerState(codecSelfer_containerArrayEnd1234)
		return
	}
	z.DecSendContainerState(codecSelfer_containerArrayElem1234)
	if r.TryDecodeAsNil() {
		x.APIVersion = ""
	} else {
		x.APIVersion = string(r.DecodeString())
	}
	yyj112++
	if yyhl112 {
		yyb112 = yyj112 > l
	} else {
		yyb112 = r.CheckBreak()
	}
	if yyb112 {
		z.DecSendContainerState(codecSelfer_containerArrayEnd1234)
		return
	}
	z.DecSendContainerState(codecSelfer_containerArrayElem1234)
	if r.TryDecodeAsNil() {
		x.ListMeta = pkg1_unversioned.ListMeta{}
	} else {
		yyv115 := &x.ListMeta
		yym116 := z.DecBinary()
		_ = yym116
		if false {
		} else if z.HasExtensions() && z.DecExt(yyv115) {
		} else {
			z.DecFallback(yyv115, false)
		}
	}
	yyj112++
	if yyhl112 {
		yyb112 = yyj112 > l
	} else {
		yyb112 = r.CheckBreak()
	}
	if yyb112 {
		z.DecSendContainerState(codecSelfer_containerArrayEnd1234)
		return
	}
	z.DecSendContainerState(codecSelfer_containerArrayElem1234)
	if r.TryDecodeAsNil() {
		x.Items = nil
	} else {
		yyv117 := &x.Items
		yym118 := z.DecBinary()
		_ = yym118
		if false {
		} else {
			h.decSlicePetSet((*[]PetSet)(yyv117), d)
		}
	}
	for {
		yyj112++
		if yyhl112 {
			yyb112 = yyj112 > l
		} else {
			yyb112 = r.CheckBreak()
		}
		if yyb112 {
			break
		}
		z.DecSendContainerState(codecSelfer_containerArrayElem1234)
		z.DecStructFieldNotFound(yyj112-1, "")
	}
	z.DecSendContainerState(codecSelfer_containerArrayEnd1234)
}

func (x codecSelfer1234) encSliceapi_PersistentVolumeClaim(v []pkg2_api.PersistentVolumeClaim, e *codec1978.Encoder) {
	var h codecSelfer1234
	z, r := codec1978.GenHelperEncoder(e)
	_, _, _ = h, z, r
	r.EncodeArrayStart(len(v))
	for _, yyv119 := range v {
		z.EncSendContainerState(codecSelfer_containerArrayElem1234)
		yy120 := &yyv119
		yy120.CodecEncodeSelf(e)
	}
	z.EncSendContainerState(codecSelfer_containerArrayEnd1234)
}

func (x codecSelfer1234) decSliceapi_PersistentVolumeClaim(v *[]pkg2_api.PersistentVolumeClaim, d *codec1978.Decoder) {
	var h codecSelfer1234
	z, r := codec1978.GenHelperDecoder(d)
	_, _, _ = h, z, r

	yyv121 := *v
	yyh121, yyl121 := z.DecSliceHelperStart()
	var yyc121 bool
	if yyl121 == 0 {
		if yyv121 == nil {
			yyv121 = []pkg2_api.PersistentVolumeClaim{}
			yyc121 = true
		} else if len(yyv121) != 0 {
			yyv121 = yyv121[:0]
			yyc121 = true
		}
	} else if yyl121 > 0 {
		var yyrr121, yyrl121 int
		var yyrt121 bool
		if yyl121 > cap(yyv121) {

			yyrg121 := len(yyv121) > 0
			yyv2121 := yyv121
			yyrl121, yyrt121 = z.DecInferLen(yyl121, z.DecBasicHandle().MaxInitLen, 368)
			if yyrt121 {
				if yyrl121 <= cap(yyv121) {
					yyv121 = yyv121[:yyrl121]
				} else {
					yyv121 = make([]pkg2_api.PersistentVolumeClaim, yyrl121)
				}
			} else {
				yyv121 = make([]pkg2_api.PersistentVolumeClaim, yyrl121)
			}
			yyc121 = true
			yyrr121 = len(yyv121)
			if yyrg121 {
				copy(yyv121, yyv2121)
			}
		} else if yyl121 != len(yyv121) {
			yyv121 = yyv121[:yyl121]
			yyc121 = true
		}
		yyj121 := 0
		for ; yyj121 < yyrr121; yyj121++ {
			yyh121.ElemContainerState(yyj121)
			if r.TryDecodeAsNil() {
				yyv121[yyj121] = pkg2_api.PersistentVolumeClaim{}
			} else {
				yyv122 := &yyv121[yyj121]
				yyv122.CodecDecodeSelf(d)
			}

		}
		if yyrt121 {
			for ; yyj121 < yyl121; yyj121++ {
				yyv121 = append(yyv121, pkg2_api.PersistentVolumeClaim{})
				yyh121.ElemContainerState(yyj121)
				if r.TryDecodeAsNil() {
					yyv121[yyj121] = pkg2_api.PersistentVolumeClaim{}
				} else {
					yyv123 := &yyv121[yyj121]
					yyv123.CodecDecodeSelf(d)
				}

			}
		}

	} else {
		yyj121 := 0
		for ; !r.CheckBreak(); yyj121++ {

			if yyj121 >= len(yyv121) {
				yyv121 = append(yyv121, pkg2_api.PersistentVolumeClaim{}) // var yyz121 pkg2_api.PersistentVolumeClaim
				yyc121 = true
			}
			yyh121.ElemContainerState(yyj121)
			if yyj121 < len(yyv121) {
				if r.TryDecodeAsNil() {
					yyv121[yyj121] = pkg2_api.PersistentVolumeClaim{}
				} else {
					yyv124 := &yyv121[yyj121]
					yyv124.CodecDecodeSelf(d)
				}

			} else {
				z.DecSwallow()
			}

		}
		if yyj121 < len(yyv121) {
			yyv121 = yyv121[:yyj121]
			yyc121 = true
		} else if yyj121 == 0 && yyv121 == nil {
			yyv121 = []pkg2_api.PersistentVolumeClaim{}
			yyc121 = true
		}
	}
	yyh121.End()
	if yyc121 {
		*v = yyv121
	}
}

func (x codecSelfer1234) encSlicePetSet(v []PetSet, e *codec1978.Encoder) {
	var h codecSelfer1234
	z, r := codec1978.GenHelperEncoder(e)
	_, _, _ = h, z, r
	r.EncodeArrayStart(len(v))
	for _, yyv125 := range v {
		z.EncSendContainerState(codecSelfer_containerArrayElem1234)
		yy126 := &yyv125
		yy126.CodecEncodeSelf(e)
	}
	z.EncSendContainerState(codecSelfer_containerArrayEnd1234)
}

func (x codecSelfer1234) decSlicePetSet(v *[]PetSet, d *codec1978.Decoder) {
	var h codecSelfer1234
	z, r := codec1978.GenHelperDecoder(d)
	_, _, _ = h, z, r

	yyv127 := *v
	yyh127, yyl127 := z.DecSliceHelperStart()
	var yyc127 bool
	if yyl127 == 0 {
		if yyv127 == nil {
			yyv127 = []PetSet{}
			yyc127 = true
		} else if len(yyv127) != 0 {
			yyv127 = yyv127[:0]
			yyc127 = true
		}
	} else if yyl127 > 0 {
		var yyrr127, yyrl127 int
		var yyrt127 bool
		if yyl127 > cap(yyv127) {

			yyrg127 := len(yyv127) > 0
			yyv2127 := yyv127
			yyrl127, yyrt127 = z.DecInferLen(yyl127, z.DecBasicHandle().MaxInitLen, 776)
			if yyrt127 {
				if yyrl127 <= cap(yyv127) {
					yyv127 = yyv127[:yyrl127]
				} else {
					yyv127 = make([]PetSet, yyrl127)
				}
			} else {
				yyv127 = make([]PetSet, yyrl127)
			}
			yyc127 = true
			yyrr127 = len(yyv127)
			if yyrg127 {
				copy(yyv127, yyv2127)
			}
		} else if yyl127 != len(yyv127) {
			yyv127 = yyv127[:yyl127]
			yyc127 = true
		}
		yyj127 := 0
		for ; yyj127 < yyrr127; yyj127++ {
			yyh127.ElemContainerState(yyj127)
			if r.TryDecodeAsNil() {
				yyv127[yyj127] = PetSet{}
			} else {
				yyv128 := &yyv127[yyj127]
				yyv128.CodecDecodeSelf(d)
			}

		}
		if yyrt127 {
			for ; yyj127 < yyl127; yyj127++ {
				yyv127 = append(yyv127, PetSet{})
				yyh127.ElemContainerState(yyj127)
				if r.TryDecodeAsNil() {
					yyv127[yyj127] = PetSet{}
				} else {
					yyv129 := &yyv127[yyj127]
					yyv129.CodecDecodeSelf(d)
				}

			}
		}

	} else {
		yyj127 := 0
		for ; !r.CheckBreak(); yyj127++ {

			if yyj127 >= len(yyv127) {
				yyv127 = append(yyv127, PetSet{}) // var yyz127 PetSet
				yyc127 = true
			}
			yyh127.ElemContainerState(yyj127)
			if yyj127 < len(yyv127) {
				if r.TryDecodeAsNil() {
					yyv127[yyj127] = PetSet{}
				} else {
					yyv130 := &yyv127[yyj127]
					yyv130.CodecDecodeSelf(d)
				}

			} else {
				z.DecSwallow()
			}

		}
		if yyj127 < len(yyv127) {
			yyv127 = yyv127[:yyj127]
			yyc127 = true
		} else if yyj127 == 0 && yyv127 == nil {
			yyv127 = []PetSet{}
			yyc127 = true
		}
	}
	yyh127.End()
	if yyc127 {
		*v = yyv127
	}
}
