//! The typed codec. It shares the offset and padding helpers of `de` and
//! `ser` with the `Value` codec.

use std::marker::PhantomData;

use crate::de::{check_padding, exact, offset_size_for, read_offset, split_variant};
use crate::ser::{choose_offset_size, write_offset};
use crate::ty::align_up;
use crate::{Error, Result, Type, Value};

/// The type-level facts of a type that encodes as GVariant.
///
/// The facts are the signature, the alignment, and the fixed size.
/// [`GvEncode`] and [`GvDecode`] both require this trait, so a type states
/// the three constants once for both directions.
///
/// The framing of a traversal uses only [`ALIGNMENT`] and [`FIXED_SIZE`].
/// These two constants compose in `const` context, so the read path parses
/// no type signature.
///
/// # Implementations
///
/// This crate implements the traits for the scalar and container building
/// blocks:
///
/// - `bool`, `u8`, `u32`, `u64`, `&str`, and `&[u8]` implement all three
///   traits.
/// - `String` and [`Slice`] implement [`GvType`] and [`GvEncode`].
/// - [`ArrayIter`], [`Variant`], and [`VariantBytes`] implement all three
///   traits.
/// - A tuple of 2 to 8 members implements each trait that all of its members
///   implement. A one-member tuple implements none of them.
///
/// The ostree object structs in `ostrya-core` implement the traits. These
/// impls apply the value-level conventions: big-endian scalars,
/// checksum-length checks, and sort-order checks.
///
/// [`ALIGNMENT`]: GvType::ALIGNMENT
/// [`FIXED_SIZE`]: GvType::FIXED_SIZE
pub trait GvType {
    /// The GVariant type signature, or `""` for a container type.
    ///
    /// The impls for scalars, strings, byte arrays, and variants set it. The
    /// object structs of `ostrya-core` set it too. The impls for tuples,
    /// [`ArrayIter`], and [`Slice`] leave it empty, because their element
    /// types give the signature. The encoder does not read it.
    const SIGNATURE: &'static str = "";
    /// The alignment of the serialized form, in bytes.
    const ALIGNMENT: usize;
    /// The serialized size, or `None` for a variable-size type.
    const FIXED_SIZE: Option<usize>;
}

/// A type that writes itself as normal-form GVariant bytes.
///
/// [`encode`](GvEncode::encode) writes the bytes directly and builds no
/// [`Value`] tree. The bytes equal the output of [`to_bytes`] for the same
/// type and value. The tests in `tests/differential.rs` check this for each
/// ostree object shape.
///
/// `encode` appends the value at the current end of `out`. A container impl
/// pads each member to its alignment, so the top-level call needs only an
/// empty or already-aligned buffer.
///
/// [`to_bytes`]: crate::to_bytes
pub trait GvEncode: GvType {
    /// Appends the normal-form bytes of `self` to `out`.
    ///
    /// # Errors
    ///
    /// - [`Error::InvalidValue`] if a `&str` or a `String` holds an interior
    ///   NUL byte.
    /// - For a tuple or a [`Slice`], the first error of a member.
    ///
    /// The other impls of this crate return no error.
    fn encode(&self, out: &mut Vec<u8>) -> Result<()>;
}

/// A type that reads itself from normal-form GVariant bytes.
///
/// [`decode`](GvDecode::decode) reads the fields in place and builds no
/// [`Value`] tree. A value that decodes encodes again to the input bytes,
/// because the typed path shares the offset and padding helpers of
/// [`from_bytes`] and [`to_bytes`].
///
/// The decode of an [`ArrayIter`] checks only the outer framing of the array.
/// The iterator checks each element when it visits the element. A full drain
/// of the iterator applies the same checks as [`from_bytes`].
///
/// # Allocation
///
/// A decode borrows from `data`:
///
/// - A string decodes as `&str`.
/// - A byte array decodes as `&[u8]`.
/// - An array decodes as [`ArrayIter`], a lazy iterator over the framing
///   offsets.
/// - A variant decodes as [`VariantBytes`], the borrowed child bytes and
///   signature.
///
/// With these types, the traversal of a read-heavy object does no heap
/// allocation. A dirtree walk and an xattr scan are such traversals. The test
/// `tests/alloc.rs` checks this property.
///
/// [`Variant`] is the exception. Its decode parses the child into a [`Value`],
/// and this allocates.
///
/// # Examples
///
/// ```
/// use ostrya_gvariant::{ArrayIter, GvDecode, Slice, encode_to_vec};
///
/// let bytes = encode_to_vec(&(7u32, Slice(&["a", "bc"])))?;
/// let (n, names) = <(u32, ArrayIter<&str>)>::decode(&bytes)?;
/// assert_eq!(n, 7);
/// let names: Vec<&str> = names.collect::<Result<_, _>>()?;
/// assert_eq!(names, ["a", "bc"]);
/// # Ok::<(), ostrya_gvariant::Error>(())
/// ```
///
/// [`from_bytes`]: crate::from_bytes
/// [`to_bytes`]: crate::to_bytes
pub trait GvDecode<'a>: GvType + Sized {
    /// Decodes a value from the slice that covers exactly its serialized form.
    ///
    /// # Errors
    ///
    /// - [`Error::NotNormal`] if `data` is not in normal form:
    ///   - a scalar of the wrong size, or a boolean that is not 0 or 1
    ///   - a string that is not NUL-terminated, that holds an interior NUL
    ///     byte, or that is not UTF-8
    ///   - an array or a tuple with a wrong size or nonzero padding
    ///   - framing offsets out of order or out of bounds, or an offset size
    ///     that is not the smallest that fits
    ///   - a variant with no type separator, or with a signature that is not
    ///     UTF-8 or not a valid type
    /// - [`Error::DepthExceeded`] if the child of a [`Variant`] exceeds the
    ///   [depth limit](crate::from_bytes#depth-limit) of [`from_bytes`].
    ///
    /// An [`ArrayIter`] returns the error of an element from
    /// [`next`](Iterator::next), when it visits that element.
    ///
    /// [`from_bytes`]: crate::from_bytes
    fn decode(data: &'a [u8]) -> Result<Self>;
}

/// Encodes a top-level value into a new byte vector.
///
/// # Errors
///
/// The errors of [`GvEncode::encode`].
pub fn encode_to_vec<T: GvEncode>(value: &T) -> Result<Vec<u8>> {
    let mut out = Vec::new();
    value.encode(&mut out)?;
    Ok(out)
}

// -- scalar leaves ---------------------------------------------------------

impl GvType for bool {
    const SIGNATURE: &'static str = "b";
    const ALIGNMENT: usize = 1;
    const FIXED_SIZE: Option<usize> = Some(1);
}

impl GvEncode for bool {
    fn encode(&self, out: &mut Vec<u8>) -> Result<()> {
        out.push(*self as u8);
        Ok(())
    }
}

impl<'a> GvDecode<'a> for bool {
    fn decode(data: &'a [u8]) -> Result<Self> {
        match exact::<1>(data)?[0] {
            0 => Ok(false),
            1 => Ok(true),
            _ => Err(Error::NotNormal("boolean is not 0 or 1")),
        }
    }
}

impl GvType for u8 {
    const SIGNATURE: &'static str = "y";
    const ALIGNMENT: usize = 1;
    const FIXED_SIZE: Option<usize> = Some(1);
}

impl GvEncode for u8 {
    fn encode(&self, out: &mut Vec<u8>) -> Result<()> {
        out.push(*self);
        Ok(())
    }
}

impl<'a> GvDecode<'a> for u8 {
    fn decode(data: &'a [u8]) -> Result<Self> {
        Ok(exact::<1>(data)?[0])
    }
}

impl GvType for u32 {
    const SIGNATURE: &'static str = "u";
    const ALIGNMENT: usize = 4;
    const FIXED_SIZE: Option<usize> = Some(4);
}

impl GvEncode for u32 {
    fn encode(&self, out: &mut Vec<u8>) -> Result<()> {
        out.extend_from_slice(&self.to_le_bytes());
        Ok(())
    }
}

impl<'a> GvDecode<'a> for u32 {
    fn decode(data: &'a [u8]) -> Result<Self> {
        Ok(u32::from_le_bytes(exact(data)?))
    }
}

impl GvType for u64 {
    const SIGNATURE: &'static str = "t";
    const ALIGNMENT: usize = 8;
    const FIXED_SIZE: Option<usize> = Some(8);
}

impl GvEncode for u64 {
    fn encode(&self, out: &mut Vec<u8>) -> Result<()> {
        out.extend_from_slice(&self.to_le_bytes());
        Ok(())
    }
}

impl<'a> GvDecode<'a> for u64 {
    fn decode(data: &'a [u8]) -> Result<Self> {
        Ok(u64::from_le_bytes(exact(data)?))
    }
}

// -- string and byte array -------------------------------------------------

impl GvType for &str {
    const SIGNATURE: &'static str = "s";
    const ALIGNMENT: usize = 1;
    const FIXED_SIZE: Option<usize> = None;
}

impl GvEncode for &str {
    fn encode(&self, out: &mut Vec<u8>) -> Result<()> {
        let s: &str = self;
        if s.as_bytes().contains(&0) {
            return Err(Error::InvalidValue("string contains an interior NUL byte"));
        }
        out.extend_from_slice(s.as_bytes());
        out.push(0);
        Ok(())
    }
}

impl<'a> GvDecode<'a> for &'a str {
    fn decode(data: &'a [u8]) -> Result<Self> {
        let Some((&0, content)) = data.split_last() else {
            return Err(Error::NotNormal("string is not NUL-terminated"));
        };
        if content.contains(&0) {
            return Err(Error::NotNormal("string contains an interior NUL byte"));
        }
        std::str::from_utf8(content).map_err(|_| Error::NotNormal("string is not valid UTF-8"))
    }
}

impl GvType for String {
    const SIGNATURE: &'static str = "s";
    const ALIGNMENT: usize = 1;
    const FIXED_SIZE: Option<usize> = None;
}

/// Writes the same bytes as `&str`.
///
/// An owned string can be a tuple or array member. An owned value, for
/// example a dirtree entry name, needs no reborrow into a temporary slice of
/// references.
impl GvEncode for String {
    fn encode(&self, out: &mut Vec<u8>) -> Result<()> {
        self.as_str().encode(out)
    }
}

impl GvType for &[u8] {
    const SIGNATURE: &'static str = "ay";
    const ALIGNMENT: usize = 1;
    const FIXED_SIZE: Option<usize> = None;
}

impl GvEncode for &[u8] {
    fn encode(&self, out: &mut Vec<u8>) -> Result<()> {
        out.extend_from_slice(self);
        Ok(())
    }
}

impl<'a> GvDecode<'a> for &'a [u8] {
    fn decode(data: &'a [u8]) -> Result<Self> {
        Ok(data)
    }
}

// -- arrays ----------------------------------------------------------------

/// A lazy reader over the elements of a serialized array.
///
/// It holds only the backing slice and a cursor, so iteration allocates
/// nothing.
#[derive(Clone, Copy)]
pub(crate) struct ArrayReader<'a> {
    data: &'a [u8],
    elem_alignment: usize,
    /// `Some` for a fixed-size element type.
    ///
    /// If `Some`, the elements pack back to back. If `None`, framing offsets
    /// delimit the elements.
    elem_size: Option<usize>,
    /// The framing-offset size, for variable-element arrays only.
    z: usize,
    /// The end of the element data, where the framing area starts.
    ///
    /// It applies to variable-element arrays only.
    data_end: usize,
    /// Element count.
    n: usize,
    /// Next element index.
    i: usize,
    /// The current data position, which is the cursor for variable elements.
    pos: usize,
}

impl<'a> ArrayReader<'a> {
    pub(crate) fn new(
        data: &'a [u8],
        elem_alignment: usize,
        elem_fixed_size: Option<usize>,
    ) -> Result<Self> {
        let mut r = ArrayReader {
            data,
            elem_alignment,
            elem_size: elem_fixed_size,
            z: 0,
            data_end: 0,
            n: 0,
            i: 0,
            pos: 0,
        };
        if data.is_empty() {
            return Ok(r);
        }
        if let Some(size) = elem_fixed_size {
            if !data.len().is_multiple_of(size) {
                return Err(Error::NotNormal(
                    "array size is not a multiple of the element size",
                ));
            }
            r.n = data.len() / size;
            return Ok(r);
        }
        let z = offset_size_for(data.len());
        if data.len() < z {
            return Err(Error::NotNormal("array is too small for its framing"));
        }
        let data_end = read_offset(&data[data.len() - z..], z);
        if data_end > data.len() - z {
            return Err(Error::NotNormal("array framing offset is out of bounds"));
        }
        let offsets_len = data.len() - data_end;
        if !offsets_len.is_multiple_of(z) {
            return Err(Error::NotNormal("array framing area has a partial offset"));
        }
        r.z = z;
        r.data_end = data_end;
        r.n = offsets_len / z;
        // Normal form uses the smallest offset size that fits the element data
        // plus its own offsets. A wider size re-encodes to fewer bytes, so
        // this check rejects a buffer that does not re-encode to its bytes.
        if choose_offset_size(data_end, r.n) != z {
            return Err(Error::NotNormal(
                "array framing offset size is not normal-form",
            ));
        }
        Ok(r)
    }

    /// The full serialized array slice, with the framing area.
    fn bytes(&self) -> &'a [u8] {
        self.data
    }

    /// The element count carved from the framing.
    pub(crate) fn len(&self) -> usize {
        self.n
    }

    pub(crate) fn next_slice(&mut self) -> Option<Result<&'a [u8]>> {
        if self.i >= self.n {
            return None;
        }
        let idx = self.i;
        self.i += 1;
        if let Some(size) = self.elem_size {
            let start = idx * size;
            return Some(Ok(&self.data[start..start + size]));
        }
        let off_at = self.data_end + idx * self.z;
        let end = read_offset(&self.data[off_at..off_at + self.z], self.z);
        let start = align_up(self.pos, self.elem_alignment);
        if start > end || end > self.data_end {
            // A framing error leaves `pos` unusable. Fuse the reader.
            self.i = self.n;
            return Some(Err(Error::NotNormal(
                "array element offsets are out of order",
            )));
        }
        if let Err(e) = check_padding(&self.data[self.pos..start]) {
            self.i = self.n;
            return Some(Err(e));
        }
        let slice = &self.data[start..end];
        self.pos = end;
        Some(Ok(slice))
    }
}

/// A lazy iterator over the elements of a serialized array.
///
/// `ArrayIter` borrows the source buffer and yields `Result<E>`. It decodes
/// one element in each step, so the normal-form check of an element runs when
/// the iterator visits it. It is `Copy`, so a caller can iterate it again from
/// the start.
///
/// A framing error fuses the iterator. The iterator yields the `Err` once,
/// and every later call returns `None`.
///
/// Its [`SIGNATURE`](GvType::SIGNATURE) is `""`, because the signature of an
/// array comes from its element type.
#[derive(Clone, Copy)]
pub struct ArrayIter<'a, E> {
    reader: ArrayReader<'a>,
    _marker: PhantomData<fn() -> E>,
}

impl<'a, E: GvDecode<'a>> Iterator for ArrayIter<'a, E> {
    type Item = Result<E>;
    fn next(&mut self) -> Option<Result<E>> {
        match self.reader.next_slice()? {
            Ok(slice) => Some(E::decode(slice)),
            Err(e) => Some(Err(e)),
        }
    }
}

impl<'a, E: GvType> GvType for ArrayIter<'a, E> {
    const ALIGNMENT: usize = E::ALIGNMENT;
    const FIXED_SIZE: Option<usize> = None;
}

impl<'a, E: GvDecode<'a>> GvDecode<'a> for ArrayIter<'a, E> {
    fn decode(data: &'a [u8]) -> Result<Self> {
        Ok(ArrayIter {
            reader: ArrayReader::new(data, E::ALIGNMENT, E::FIXED_SIZE)?,
            _marker: PhantomData,
        })
    }
}

impl<'a, E: GvDecode<'a>> GvEncode for ArrayIter<'a, E> {
    /// Writes the bytes of the borrowed array again.
    ///
    /// The backing slice of the reader is already in normal form. At the same
    /// alignment, the slice gives its original bytes.
    fn encode(&self, out: &mut Vec<u8>) -> Result<()> {
        out.extend_from_slice(self.reader.bytes());
        Ok(())
    }
}

/// An array to encode from a Rust slice of encodable elements.
///
/// Its [`SIGNATURE`](GvType::SIGNATURE) is `""`, because the signature of an
/// array comes from its element type.
pub struct Slice<'s, E>(pub &'s [E]);

impl<'s, E: GvEncode> GvType for Slice<'s, E> {
    const ALIGNMENT: usize = E::ALIGNMENT;
    const FIXED_SIZE: Option<usize> = None;
}

impl<'s, E: GvEncode> GvEncode for Slice<'s, E> {
    fn encode(&self, out: &mut Vec<u8>) -> Result<()> {
        write_array(
            out,
            E::ALIGNMENT,
            E::FIXED_SIZE.is_some(),
            self.0.len(),
            |out, i| self.0[i].encode(out),
        )
    }
}

/// Appends `n` array elements with normal-form framing to `out`.
///
/// `write_elem(out, i)` appends element `i`. This function writes the padding
/// and the framing-offset area. The framing is the same as the framing that
/// [`to_bytes`] writes.
///
/// The other parameters describe the element type:
///
/// - `elem_alignment`: the alignment of the element type, in bytes. If
///   `elem_fixed` is `false`, the function pads to it before each element.
/// - `elem_fixed`: `true` if the element type has a fixed size. Fixed-size
///   elements pack back to back with no padding and no framing offsets.
/// - `n`: the number of elements.
///
/// A caller with its own element storage can write the array framing with
/// this function. An example is the owned field arrays of an ostree object.
/// The caller needs no collected element references.
///
/// # Errors
///
/// The first error that `write_elem` returns, unchanged. The function has no
/// error of its own.
///
/// [`to_bytes`]: crate::to_bytes
pub fn write_array<F>(
    out: &mut Vec<u8>,
    elem_alignment: usize,
    elem_fixed: bool,
    n: usize,
    mut write_elem: F,
) -> Result<()>
where
    F: FnMut(&mut Vec<u8>, usize) -> Result<()>,
{
    let start = out.len();
    if elem_fixed {
        // A fixed size is a multiple of the element alignment, so the
        // elements pack back to back with no padding and no framing offsets.
        for i in 0..n {
            write_elem(out, i)?;
        }
        return Ok(());
    }
    let mut ends = Vec::with_capacity(n);
    for i in 0..n {
        pad_to(out, elem_alignment);
        write_elem(out, i)?;
        ends.push(out.len() - start);
    }
    if !ends.is_empty() {
        let z = choose_offset_size(out.len() - start, ends.len());
        for &end in &ends {
            write_offset(out, end, z);
        }
    }
    Ok(())
}

// -- variant ---------------------------------------------------------------

/// A decoded variant that holds the type and the value of its child.
///
/// A variant carries a dynamic child type, so [`decode`](GvDecode::decode)
/// parses the child into a [`Value`] once and keeps it. [`Variant::value`]
/// borrows that value. It walks no bytes again and clones nothing.
///
/// `Variant` is the one building block that allocates on decode. Variants
/// occur only inside `a{sv}` metadata, so a dirtree walk or an xattr scan does
/// not decode one.
///
/// A `Variant` also keeps the borrowed child bytes and signature.
/// [`encode`](GvEncode::encode) writes them again, so the output equals the
/// input byte for byte. The encode builds no signature string.
pub struct Variant<'a> {
    ty: Type,
    child: &'a [u8],
    signature: &'a [u8],
    value: Value,
}

impl<'a> Variant<'a> {
    /// Returns the type of the child.
    pub fn ty(&self) -> &Type {
        &self.ty
    }

    /// Returns the child as a [`Value`] that [`decode`](GvDecode::decode)
    /// parsed once.
    pub fn value(&self) -> &Value {
        &self.value
    }
}

impl<'a> GvType for Variant<'a> {
    const SIGNATURE: &'static str = "v";
    const ALIGNMENT: usize = 8;
    const FIXED_SIZE: Option<usize> = None;
}

impl<'a> GvDecode<'a> for Variant<'a> {
    fn decode(data: &'a [u8]) -> Result<Self> {
        let (child, signature, ty) = split_variant(data)?;
        // Walk the child once, as `from_bytes` does for `v`, and keep the value.
        let value = crate::from_bytes(&ty, child)?;
        Ok(Variant {
            ty,
            child,
            signature,
            value,
        })
    }
}

impl<'a> GvEncode for Variant<'a> {
    fn encode(&self, out: &mut Vec<u8>) -> Result<()> {
        out.extend_from_slice(self.child);
        out.push(0);
        out.extend_from_slice(self.signature);
        Ok(())
    }
}

/// A variant read in place, as borrowed child bytes and signature.
///
/// [`decode`](GvDecode::decode) splits the variant at its type separator and
/// checks that the signature is UTF-8. It parses neither the signature nor
/// the child, so it allocates nothing.
///
/// If a caller needs a checked child, the caller runs [`validate`] over the
/// whole serialized value first.
///
/// [`validate`]: crate::validate
#[derive(Clone, Copy)]
pub struct VariantBytes<'a> {
    child: &'a [u8],
    signature: &'a str,
}

impl<'a> VariantBytes<'a> {
    /// Returns the serialized child.
    pub fn child(&self) -> &'a [u8] {
        self.child
    }

    /// Returns the type signature of the child, as the variant spells it.
    ///
    /// The decode checks only that the signature is UTF-8. It does not parse
    /// the signature, so the signature can be an invalid type string.
    pub fn signature(&self) -> &'a str {
        self.signature
    }
}

impl<'a> GvType for VariantBytes<'a> {
    const SIGNATURE: &'static str = "v";
    const ALIGNMENT: usize = 8;
    const FIXED_SIZE: Option<usize> = None;
}

impl<'a> GvEncode for VariantBytes<'a> {
    /// Writes the child bytes, the type separator, and the signature again.
    ///
    /// The output equals the bytes that decode read.
    fn encode(&self, out: &mut Vec<u8>) -> Result<()> {
        out.extend_from_slice(self.child);
        out.push(0);
        out.extend_from_slice(self.signature.as_bytes());
        Ok(())
    }
}

impl<'a> GvDecode<'a> for VariantBytes<'a> {
    fn decode(data: &'a [u8]) -> Result<Self> {
        let Some(sep) = data.iter().rposition(|&b| b == 0) else {
            return Err(Error::NotNormal("variant lacks a type separator"));
        };
        let signature = std::str::from_utf8(&data[sep + 1..])
            .map_err(|_| Error::NotNormal("variant type signature is not UTF-8"))?;
        Ok(VariantBytes {
            child: &data[..sep],
            signature,
        })
    }
}

// -- tuples ----------------------------------------------------------------

/// The alignment of a container: the greatest member alignment, at least 1.
pub(crate) const fn max_align(aligns: &[usize]) -> usize {
    let mut m = 1;
    let mut i = 0;
    while i < aligns.len() {
        if aligns[i] > m {
            m = aligns[i];
        }
        i += 1;
    }
    m
}

/// The fixed size of a struct from the `(alignment, fixed_size)` of each
/// member.
///
/// If any member is variable-size, the result is `None`. The result matches
/// `Type::fixed_size`.
pub(crate) const fn struct_fixed_size(
    members: &[(usize, Option<usize>)],
    whole_align: usize,
) -> Option<usize> {
    if members.is_empty() {
        return Some(1);
    }
    let mut size = 0;
    let mut i = 0;
    while i < members.len() {
        let (align, fixed) = members[i];
        match fixed {
            Some(f) => size = align_up(size, align) + f,
            None => return None,
        }
        i += 1;
    }
    Some(align_up(size, whole_align))
}

/// A cursor that splits a serialized tuple or dict-entry body into member
/// slices.
///
/// It applies the same framing and padding checks as `from_bytes`.
pub(crate) struct TupleReader<'a> {
    data: &'a [u8],
    framing_start: usize,
    z: usize,
    pos: usize,
    offset_index: usize,
    fixed: bool,
}

impl<'a> TupleReader<'a> {
    pub(crate) fn new(data: &'a [u8], n_offsets: usize, fixed_size: Option<usize>) -> Result<Self> {
        if let Some(size) = fixed_size
            && data.len() != size
        {
            return Err(Error::NotNormal("fixed-size tuple has the wrong size"));
        }
        let z = offset_size_for(data.len());
        let framing_start = data
            .len()
            .checked_sub(n_offsets * z)
            .ok_or(Error::NotNormal("tuple is too small for its framing"))?;
        // If framing offsets are present, the offset size must be the size
        // that the encoder picks for this member area. A wider size re-encodes
        // to fewer bytes, so this check rejects it. A tuple carries no offsets
        // if all of its members are fixed-size, or if its last member is the
        // only variable-size member. For such a tuple, `z` has no effect.
        if n_offsets > 0 && choose_offset_size(framing_start, n_offsets) != z {
            return Err(Error::NotNormal(
                "tuple framing offset size is not normal-form",
            ));
        }
        Ok(TupleReader {
            data,
            framing_start,
            z,
            pos: 0,
            offset_index: 0,
            fixed: fixed_size.is_some(),
        })
    }

    pub(crate) fn field(
        &mut self,
        alignment: usize,
        fixed_size: Option<usize>,
        is_last: bool,
    ) -> Result<&'a [u8]> {
        let start = align_up(self.pos, alignment);
        let end = if let Some(size) = fixed_size {
            start.checked_add(size)
        } else if is_last {
            Some(self.framing_start)
        } else {
            let at = self.data.len() - (self.offset_index + 1) * self.z;
            self.offset_index += 1;
            Some(read_offset(&self.data[at..at + self.z], self.z))
        };
        let end = end.ok_or(Error::NotNormal("tuple member offset overflows"))?;
        if start > end || end > self.framing_start {
            return Err(Error::NotNormal("tuple member offsets are out of order"));
        }
        check_padding(&self.data[self.pos..start])?;
        let slice = &self.data[start..end];
        self.pos = end;
        Ok(slice)
    }

    pub(crate) fn finish(self) -> Result<()> {
        if self.fixed {
            check_padding(&self.data[self.pos..])
        } else if self.pos != self.framing_start {
            Err(Error::NotNormal("tuple members do not fill the tuple"))
        } else {
            Ok(())
        }
    }
}

/// A writer that appends tuple members with correct alignment, padding, and
/// framing offsets.
///
/// It writes the same bytes as `to_bytes`.
pub(crate) struct TupleWriter<'b> {
    out: &'b mut Vec<u8>,
    start: usize,
    /// The end offsets of the variable-size members other than the last, in
    /// member order.
    ///
    /// [`finish`](Self::finish) writes them in reverse order.
    offsets: Vec<usize>,
}

impl<'b> TupleWriter<'b> {
    /// Creates a writer that appends members at the end of `out`.
    ///
    /// The offsets buffer starts empty and grows only for variable-size
    /// members, so a fully fixed-size tuple allocates nothing.
    pub(crate) fn new(out: &'b mut Vec<u8>) -> Self {
        let start = out.len();
        TupleWriter {
            out,
            start,
            offsets: Vec::new(),
        }
    }

    /// Appends a member with a runtime alignment and fixed size.
    ///
    /// `write` encodes the member. The framing rule exists here once for the
    /// typed encoder and the `Value` encoder.
    pub(crate) fn field_dyn(
        &mut self,
        alignment: usize,
        fixed_size: Option<usize>,
        is_last: bool,
        write: impl FnOnce(&mut Vec<u8>) -> Result<()>,
    ) -> Result<()> {
        pad_to(self.out, alignment);
        write(self.out)?;
        if !is_last && fixed_size.is_none() {
            self.offsets.push(self.out.len() - self.start);
        }
        Ok(())
    }

    pub(crate) fn field<T: GvEncode>(&mut self, value: &T, is_last: bool) -> Result<()> {
        self.field_dyn(T::ALIGNMENT, T::FIXED_SIZE, is_last, |out| {
            value.encode(out)
        })
    }

    pub(crate) fn finish(self, fixed_size: Option<usize>) {
        if let Some(size) = fixed_size {
            // All members fixed: pad the end to the tuple alignment.
            self.out.resize(self.start + size, 0);
        } else if !self.offsets.is_empty() {
            let z = choose_offset_size(self.out.len() - self.start, self.offsets.len());
            for &end in self.offsets.iter().rev() {
                write_offset(self.out, end, z);
            }
        }
    }
}

pub(crate) fn pad_to(out: &mut Vec<u8>, alignment: usize) {
    out.resize(align_up(out.len(), alignment), 0);
}

macro_rules! impl_tuple {
    ($($T:ident $idx:tt),+ ; $Last:ident $last_idx:tt) => {
        impl<$($T: GvType,)+ $Last: GvType> GvType for ($($T,)+ $Last,) {
            const ALIGNMENT: usize = max_align(&[$($T::ALIGNMENT,)+ $Last::ALIGNMENT]);
            const FIXED_SIZE: Option<usize> = struct_fixed_size(
                &[$(($T::ALIGNMENT, $T::FIXED_SIZE),)+ ($Last::ALIGNMENT, $Last::FIXED_SIZE)],
                max_align(&[$($T::ALIGNMENT,)+ $Last::ALIGNMENT]),
            );
        }

        impl<'a, $($T: GvDecode<'a>,)+ $Last: GvDecode<'a>> GvDecode<'a> for ($($T,)+ $Last,) {
            fn decode(data: &'a [u8]) -> Result<Self> {
                let n_offsets = [$($T::FIXED_SIZE.is_none(),)+]
                    .into_iter()
                    .filter(|&v| v)
                    .count();
                let mut r = TupleReader::new(data, n_offsets, <Self as GvType>::FIXED_SIZE)?;
                let value = (
                    $( <$T as GvDecode<'a>>::decode(r.field($T::ALIGNMENT, $T::FIXED_SIZE, false)?)?, )+
                    <$Last as GvDecode<'a>>::decode(r.field($Last::ALIGNMENT, $Last::FIXED_SIZE, true)?)?,
                );
                r.finish()?;
                Ok(value)
            }
        }

        impl<$($T: GvEncode,)+ $Last: GvEncode> GvEncode for ($($T,)+ $Last,) {
            fn encode(&self, out: &mut Vec<u8>) -> Result<()> {
                let mut w = TupleWriter::new(out);
                $( w.field(&self.$idx, false)?; )+
                w.field(&self.$last_idx, true)?;
                w.finish(<Self as GvType>::FIXED_SIZE);
                Ok(())
            }
        }
    };
}

impl_tuple!(A 0 ; B 1);
impl_tuple!(A 0, B 1 ; C 2);
impl_tuple!(A 0, B 1, C 2 ; D 3);
impl_tuple!(A 0, B 1, C 2, D 3 ; E 4);
impl_tuple!(A 0, B 1, C 2, D 3, E 4 ; F 5);
impl_tuple!(A 0, B 1, C 2, D 3, E 4, F 5 ; G 6);
impl_tuple!(A 0, B 1, C 2, D 3, E 4, F 5, G 6 ; H 7);

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{from_bytes, to_bytes};

    /// The `(uuua(ayay))` dirmeta shape as a borrowed view.
    type DirMetaView<'a> = (u32, u32, u32, ArrayIter<'a, (&'a [u8], &'a [u8])>);

    /// Round-trips a typed value against `to_bytes`/`from_bytes` for a signature.
    ///
    /// The typed encoding must equal the `Value` encoding. The `Value` decode
    /// of those bytes must give `expected_value`. The typed decode must
    /// re-encode to the same bytes.
    ///
    /// The caller supplies the decode-and-re-encode step as `decode_reencode`,
    /// so the borrowed view binds to the buffer that this function makes. A
    /// borrowed type such as `&str` cannot decode into a fixed lifetime that
    /// the caller chooses, so the closure decodes and re-encodes in one call.
    fn check<T, F>(sig: &str, value: &T, expected_value: &Value, decode_reencode: F)
    where
        T: GvEncode,
        F: Fn(&[u8]) -> Result<Vec<u8>>,
    {
        let ty = Type::parse(sig).unwrap();
        let typed = encode_to_vec(value).unwrap();
        let from_value = to_bytes(&ty, expected_value).unwrap();
        assert_eq!(
            typed, from_value,
            "typed encode matches Value encode for {sig}"
        );
        assert_eq!(
            from_bytes(&ty, &typed).unwrap(),
            *expected_value,
            "Value decode of typed bytes for {sig}"
        );
        assert_eq!(
            decode_reencode(&typed).unwrap(),
            typed,
            "typed decode re-encodes identically for {sig}"
        );
    }

    #[test]
    fn scalars_match_value_path() {
        check("y", &0xabu8, &Value::Byte(0xab), |b: &[u8]| {
            encode_to_vec(&<u8>::decode(b)?)
        });
        check("b", &true, &Value::Bool(true), |b: &[u8]| {
            encode_to_vec(&<bool>::decode(b)?)
        });
        check(
            "u",
            &0x0102_0304u32,
            &Value::U32(0x0102_0304),
            |b: &[u8]| encode_to_vec(&<u32>::decode(b)?),
        );
        check(
            "t",
            &0x0102_0304_0506_0708u64,
            &Value::U64(0x0102_0304_0506_0708),
            |b: &[u8]| encode_to_vec(&<u64>::decode(b)?),
        );
        check("s", &"hi", &Value::Str("hi".into()), |b: &[u8]| {
            encode_to_vec(&<&str>::decode(b)?)
        });
        let bytes: &[u8] = &[0, 1, 2, 0, 4];
        check(
            "ay",
            &bytes,
            &Value::Bytes(vec![0, 1, 2, 0, 4]),
            |b: &[u8]| encode_to_vec(&<&[u8]>::decode(b)?),
        );
    }

    #[test]
    fn dirmeta_shape_round_trips() {
        // (uuua(ayay)) with a single xattr entry.
        let xattr: (&[u8], &[u8]) = (b"user.foo", b"bar");
        let value = (
            0u32,
            0u32,
            0o40755u32.swap_bytes(),
            Slice(std::slice::from_ref(&xattr)),
        );
        let ty = Type::parse("(uuua(ayay))").unwrap();
        let typed = encode_to_vec(&value).unwrap();
        let expected = Value::Tuple(vec![
            Value::U32(0),
            Value::U32(0),
            Value::U32(0o40755u32.swap_bytes()),
            Value::Array(vec![Value::Tuple(vec![
                Value::Bytes(b"user.foo".to_vec()),
                Value::Bytes(b"bar".to_vec()),
            ])]),
        ]);
        assert_eq!(typed, to_bytes(&ty, &expected).unwrap());

        // Decode borrow-first and re-encode to identical bytes.
        let decoded = <DirMetaView as GvDecode>::decode(&typed).unwrap();
        assert_eq!(decoded.0, 0);
        assert_eq!(decoded.2, 0o40755u32.swap_bytes());
        let xattrs: Vec<(&[u8], &[u8])> = decoded.3.map(Result::unwrap).collect();
        assert_eq!(xattrs, [(b"user.foo".as_slice(), b"bar".as_slice())]);
        assert_eq!(encode_to_vec(&decoded).unwrap(), typed);
    }

    #[test]
    fn variable_tuple_with_fixed_final_member() {
        // (su): the string needs a framing offset. The trailing u32 needs none.
        let value: (&str, u32) = ("abc", 5);
        check(
            "(su)",
            &value,
            &Value::Tuple(vec!["abc".into(), Value::U32(5)]),
            |b: &[u8]| encode_to_vec(&<(&str, u32)>::decode(b)?),
        );
    }

    #[test]
    fn fixed_element_array_packs_without_offsets() {
        let items = [(1u32, 2u32, 3u32), (4, 5, 6)];
        let ty = Type::parse("a(uuu)").unwrap();
        let typed = encode_to_vec(&Slice(&items)).unwrap();
        let expected = Value::Array(vec![
            Value::Tuple(vec![Value::U32(1), Value::U32(2), Value::U32(3)]),
            Value::Tuple(vec![Value::U32(4), Value::U32(5), Value::U32(6)]),
        ]);
        assert_eq!(typed, to_bytes(&ty, &expected).unwrap());
        let decoded = <ArrayIter<(u32, u32, u32)> as GvDecode>::decode(&typed).unwrap();
        let got: Vec<(u32, u32, u32)> = decoded.map(Result::unwrap).collect();
        assert_eq!(got, items);
    }

    #[test]
    fn variant_round_trips_via_value() {
        // A dict entry {sv} with a string value. It is the a{sv} building block.
        let child = to_bytes(&Type::parse("s").unwrap(), &Value::Str("1".into())).unwrap();
        let mut variant_bytes = child.clone();
        variant_bytes.push(0);
        variant_bytes.extend_from_slice(b"s");
        let variant = Variant::decode(&variant_bytes).unwrap();
        assert_eq!(variant.ty(), &Type::Str);
        assert_eq!(variant.value(), &Value::Str("1".into()));
        assert_eq!(encode_to_vec(&variant).unwrap(), variant_bytes);

        let entry: (&str, Variant) = ("version", variant);
        let ty = Type::parse("{sv}").unwrap();
        let expected = Value::Tuple(vec![
            "version".into(),
            Value::variant(Type::Str, "1".into()),
        ]);
        assert_eq!(
            encode_to_vec(&entry).unwrap(),
            to_bytes(&ty, &expected).unwrap()
        );
    }

    /// An `a{sv}` read as `(&str, VariantBytes)` entries gives each key, the
    /// child bytes, and the child signature of each value, in order.
    #[test]
    fn variant_bytes_read_a_dict_in_place() {
        let ty = Type::parse("a{sv}").unwrap();
        let dict = Value::Array(vec![
            Value::Tuple(vec!["a".into(), Value::variant(Type::Str, "text".into())]),
            Value::Tuple(vec![
                "b".into(),
                Value::variant(
                    Type::parse("aay").unwrap(),
                    Value::Array(vec![Value::Bytes(b"xy".to_vec())]),
                ),
            ]),
        ]);
        let bytes = to_bytes(&ty, &dict).unwrap();
        let entries: Vec<(&str, VariantBytes)> =
            <ArrayIter<(&str, VariantBytes)> as GvDecode>::decode(&bytes)
                .unwrap()
                .map(Result::unwrap)
                .collect();
        assert_eq!(entries.len(), 2);
        assert_eq!(entries[0].0, "a");
        assert_eq!(entries[0].1.signature(), "s");
        assert_eq!(entries[0].1.child(), b"text\0");
        assert_eq!(entries[1].0, "b");
        assert_eq!(entries[1].1.signature(), "aay");
        assert_eq!(
            from_bytes(&Type::parse("aay").unwrap(), entries[1].1.child()).unwrap(),
            Value::Array(vec![Value::Bytes(b"xy".to_vec())])
        );
        assert_eq!(
            VariantBytes::decode(b"no separator").err(),
            Some(Error::NotNormal("variant lacks a type separator"))
        );
    }

    /// The entries of an `a{sv}`, read and written again, give the dict bytes.
    ///
    /// The test reads the entries as `(&str, VariantBytes)` and writes them
    /// again with [`write_array`]. One variant encodes to the bytes that
    /// decode read.
    #[test]
    fn variant_bytes_encode_the_bytes_they_were_read_from() {
        let ty = Type::parse("a{sv}").unwrap();
        let dict = Value::Array(vec![
            Value::Tuple(vec!["a".into(), Value::variant(Type::Str, "text".into())]),
            Value::Tuple(vec![
                "b".into(),
                Value::variant(Type::parse("t").unwrap(), Value::U64(7)),
            ]),
            Value::Tuple(vec![
                "c".into(),
                Value::variant(
                    Type::parse("aay").unwrap(),
                    Value::Array(vec![Value::Bytes(b"xy".to_vec())]),
                ),
            ]),
        ]);
        let bytes = to_bytes(&ty, &dict).unwrap();
        let entries: Vec<(&str, VariantBytes)> =
            <ArrayIter<(&str, VariantBytes)> as GvDecode>::decode(&bytes)
                .unwrap()
                .map(Result::unwrap)
                .collect();
        let mut out = Vec::new();
        write_array(&mut out, 8, false, entries.len(), |out, i| {
            entries[i].encode(out)
        })
        .unwrap();
        assert_eq!(out, bytes);

        let variant = to_bytes(&Type::Variant, &Value::variant(Type::Str, "text".into())).unwrap();
        let read = VariantBytes::decode(&variant).unwrap();
        assert_eq!(encode_to_vec(&read).unwrap(), variant);
    }

    #[test]
    fn signature_constants() {
        assert_eq!(<u32 as GvType>::SIGNATURE, "u");
        assert_eq!(<u64 as GvType>::SIGNATURE, "t");
        assert_eq!(<&str as GvType>::SIGNATURE, "s");
        assert_eq!(<&[u8] as GvType>::SIGNATURE, "ay");
        assert_eq!(<Variant as GvType>::SIGNATURE, "v");
    }

    #[test]
    fn alignment_and_fixed_size_match_type() {
        assert_eq!(<(u32, u32, u32) as GvType>::ALIGNMENT, 4);
        assert_eq!(<(u32, u32, u32) as GvType>::FIXED_SIZE, Some(12));
        assert_eq!(<(u64, u8) as GvType>::FIXED_SIZE, Some(16));
        assert_eq!(<DirMetaView<'static> as GvType>::FIXED_SIZE, None);
        assert_eq!(<DirMetaView<'static> as GvType>::ALIGNMENT, 4);
    }

    /// Constants of the typed view must agree with the parsed [`Type`].
    fn assert_consts_match<'a, T: GvEncode + GvDecode<'a>>(sig: &str) {
        let ty = Type::parse(sig).unwrap();
        assert_eq!(
            <T as GvType>::ALIGNMENT,
            ty.alignment(),
            "alignment for {sig}"
        );
        assert_eq!(
            <T as GvType>::FIXED_SIZE,
            ty.fixed_size(),
            "fixed size for {sig}"
        );
    }

    #[test]
    fn tuple_constants_match_type_for_aligned_arrays() {
        assert_consts_match::<(u8, ArrayIter<(u32, u32)>)>("(ya(uu))");
        assert_consts_match::<(&str, ArrayIter<(u32, u32, u32)>)>("(sa(uuu))");
        assert_consts_match::<(u64, &[u8], ArrayIter<(&str, Variant)>)>("(taya{sv})");
    }

    #[test]
    fn aligned_array_behind_unaligned_member_reencodes_identically() {
        // (ya(uu)): padding follows the leading byte and precedes the
        // 4-aligned array. The re-encode of the borrowed array must reproduce
        // this padding.
        let ty = Type::parse("(ya(uu))").unwrap();
        let value = Value::Tuple(vec![
            Value::Byte(7),
            Value::Array(vec![
                Value::Tuple(vec![Value::U32(1), Value::U32(2)]),
                Value::Tuple(vec![Value::U32(3), Value::U32(4)]),
            ]),
        ]);
        let bytes = to_bytes(&ty, &value).unwrap();
        let decoded = <(u8, ArrayIter<(u32, u32)>) as GvDecode>::decode(&bytes).unwrap();
        let reencoded = encode_to_vec(&decoded).unwrap();
        assert_eq!(reencoded, bytes, "(ya(uu)) re-encode is byte-identical");
        assert_eq!(from_bytes(&ty, &reencoded).unwrap(), value);

        // (sa(uuu)): a variable-size member ahead of the aligned array.
        let ty = Type::parse("(sa(uuu))").unwrap();
        let value = Value::Tuple(vec![
            "ab".into(),
            Value::Array(vec![Value::Tuple(vec![
                Value::U32(1),
                Value::U32(2),
                Value::U32(3),
            ])]),
        ]);
        let bytes = to_bytes(&ty, &value).unwrap();
        let decoded = <(&str, ArrayIter<(u32, u32, u32)>) as GvDecode>::decode(&bytes).unwrap();
        assert_eq!(
            encode_to_vec(&decoded).unwrap(),
            bytes,
            "(sa(uuu)) re-encode is byte-identical"
        );

        // (taya{sv}): an 8-aligned dict-entry array behind a byte array.
        let ty = Type::parse("(taya{sv})").unwrap();
        let value = Value::Tuple(vec![
            Value::U64(9),
            Value::Bytes(vec![0xaa, 0xbb, 0xcc]),
            Value::Array(vec![Value::Tuple(vec![
                "k".into(),
                Value::variant(Type::Str, "x".into()),
            ])]),
        ]);
        let bytes = to_bytes(&ty, &value).unwrap();
        let decoded =
            <(u64, &[u8], ArrayIter<(&str, Variant)>) as GvDecode>::decode(&bytes).unwrap();
        assert_eq!(
            encode_to_vec(&decoded).unwrap(),
            bytes,
            "(taya{{sv}}) re-encode is byte-identical"
        );
    }

    #[test]
    fn array_iter_fuses_after_framing_error() {
        // A two-element "as" whose first framing offset exceeds the data area.
        // The iterator yields the framing error once. Then iteration ends.
        let data = [b'a', 0, b'b', 0, 5, 4];
        let mut it = <ArrayIter<&str> as GvDecode>::decode(&data).unwrap();
        assert_eq!(
            it.next(),
            Some(Err(Error::NotNormal(
                "array element offsets are out of order"
            )))
        );
        assert_eq!(it.next(), None);
        assert_eq!(it.next(), None);
    }

    #[test]
    fn array_decode_defers_element_checks_to_iteration() {
        // Valid outer framing around a corrupt element. Decode succeeds. The
        // iterator yields the element error at the visit of that element.
        let data = [0xff, 0, 2];
        let mut it = <ArrayIter<&str> as GvDecode>::decode(&data).unwrap();
        assert_eq!(
            it.next(),
            Some(Err(Error::NotNormal("string is not valid UTF-8")))
        );
        assert_eq!(it.next(), None);
    }

    #[test]
    fn rejects_interior_nul_in_string() {
        let err = encode_to_vec(&"a\0b").unwrap_err();
        assert_eq!(
            err,
            Error::InvalidValue("string contains an interior NUL byte")
        );
    }

    #[test]
    fn rejects_bad_typed_bytes() {
        assert!(<u32 as GvDecode>::decode(&[1, 2, 3]).is_err());
        assert!(<&str as GvDecode>::decode(b"abc").is_err());
        assert!(<bool as GvDecode>::decode(&[2]).is_err());
    }

    #[test]
    fn rejects_non_normal_array_offset_size() {
        // A 256-byte `as` with one 254-byte string element and a 2-byte
        // framing offset. Normal form uses a 1-byte offset, 255 bytes in
        // total, so decode must reject the wider encoding. If decode accepts
        // it, a re-serialize silently gives shorter bytes with another checksum.
        let mut data = vec![b'x'; 253];
        data.push(0); // NUL terminator -> 254-byte element data area
        data.extend_from_slice(&254u16.to_le_bytes());
        assert_eq!(data.len(), 256);
        assert_eq!(
            from_bytes(&Type::parse("as").unwrap(), &data),
            Err(Error::NotNormal(
                "array framing offset size is not normal-form"
            ))
        );
    }

    #[test]
    fn rejects_non_normal_tuple_offset_size() {
        // A 256-byte `(ss)` whose single framing offset is 2 bytes. Normal
        // form uses a 1-byte offset, 255 bytes in total. The member area holds
        // the two NUL-terminated strings. The trailing offset points to the end
        // of the first string.
        let mut data = Vec::new();
        data.extend_from_slice(b"a\0"); // first string, 2 bytes
        data.extend_from_slice(&vec![b'b'; 251]);
        data.push(0); // second string, 252 bytes -> 254-byte member area
        data.extend_from_slice(&2u16.to_le_bytes()); // 2-byte offset to s1 end
        assert_eq!(data.len(), 256);
        assert_eq!(
            from_bytes(&Type::parse("(ss)").unwrap(), &data),
            Err(Error::NotNormal(
                "tuple framing offset size is not normal-form"
            ))
        );
    }
}
