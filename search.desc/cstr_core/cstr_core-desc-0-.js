searchState.loadedDescShard("cstr_core", 0, "Representation of a borrowed C string.\nA type representing an owned, C-compatible, nul-terminated …\nAn error indicating that a nul byte was not in the …\nAn error indicating invalid UTF-8 when converting a <code>CString</code>…\nAn error indicating that an interior nul byte was found.\nReturns the contents of this <code>CString</code> as a slice of bytes.\nEquivalent to the <code>as_bytes</code> function except that the …\nExtracts a <code>CStr</code> slice containing the entire string.\nReturns the inner pointer to this C string.\nRe-export c_char\nGenerate a CStr at compile time that is guaranteed to be …\nCreates an empty <code>CString</code>.\nReturns the argument unchanged.\nConverts a <code>Box</code><code>&lt;CStr&gt;</code> into a <code>CString</code> without copying or …\nReturns the argument unchanged.\nReturns the argument unchanged.\nReturns the argument unchanged.\nCreates a C string wrapper from a byte slice.\nUnsafely creates a C string wrapper from a byte slice.\nWraps a raw C string with a safe C string wrapper.\nRetakes ownership of a <code>CString</code> that was transferred to C …\nCreates a C-compatible string from a byte vector without …\nCalls <code>U::from(self)</code>.\nCalls <code>U::from(self)</code>.\nCalls <code>U::from(self)</code>.\nCalls <code>U::from(self)</code>.\nConverts this <code>CString</code> into a boxed <code>CStr</code>.\nConsumes the <code>CString</code> and returns the underlying byte …\nEquivalent to the <code>into_bytes</code> function except that the …\nConverts a <code>Box</code><code>&lt;CStr&gt;</code> into a <code>CString</code> without copying or …\nConsumes this error, returning original <code>CString</code> which …\nConsumes the <code>CString</code> and transfers ownership of the string …\nConverts the <code>CString</code> into a <code>String</code> if it contains valid …\nConsumes this error, returning the underlying vector of …\nCreates a new C-compatible string from a container of …\nReturns the position of the nul byte in the slice that was …\nConverts this C string to a byte slice.\nConverts this C string to a byte slice containing the …\nYields a <code>&amp;str</code> slice if the <code>CStr</code> contains valid UTF-8.\nConverts a <code>CStr</code> into a <code>Cow</code><code>&lt;</code>[<code>str</code>]<code>&gt;</code>.\nAccess the underlying UTF-8 error that was the cause of …")