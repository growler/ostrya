//! Typed codec layer over the serialized bytes.
//!
//! [`GvDecode`] reads fields in place from a serialized buffer and [`GvEncode`]
//! writes normal-form bytes directly, without going through the [`Value`] tree.
//! Decode is borrow-first: strings and byte arrays decode as `&str` and
//! `&[u8]` borrowing the input, and arrays decode as [`ArrayIter`], a lazy
//! iterator over the framing offsets. Traversing a read-heavy object -- a
//! dirtree walk, an xattr scan -- therefore performs no heap allocation.
//!
//! The framing is driven entirely by two associated constants,
//! [`GvType::ALIGNMENT`] and [`GvType::FIXED_SIZE`], which compose in
//! `const` context, so no type signature is parsed on the traversal path. The
//! reader and writer primitives reuse the same offset and padding helpers as
//! [`from_bytes`](crate::from_bytes) and [`to_bytes`](crate::to_bytes), so a
//! value decoded here re-encodes to the identical bytes.
//!
//! This crate stays free of ostree knowledge. The impls here cover the scalar
//! and container building blocks; the ostree object structs implement the
//! traits in a later phase, where the value-level conventions (big-endian
//! scalars, checksum-length and sort-order validation) are applied.

use std::marker::PhantomData;

use crate::de::{check_padding, exact, offset_size_for, read_offset, split_variant};
use crate::ser::{choose_offset_size, write_offset};
use crate::ty::align_up;
use crate::{Error, Result, Type, Value};

/// Type-level facts about a GVariant-encodable type: its signature, alignment,
/// and fixed size. [`GvEncode`] and [`GvDecode`] both require it, so a type
/// states these three constants once for both directions.
///
/// The framing on the traversal path is driven entirely by [`ALIGNMENT`] and
/// [`FIXED_SIZE`], which compose in `const` context, so no type signature is
/// parsed while reading.
///
/// [`ALIGNMENT`]: GvType::ALIGNMENT
/// [`FIXED_SIZE`]: GvType::FIXED_SIZE
pub trait GvType {
    /// The GVariant type signature, for the nameable leaf and object types.
    /// Composite container impls (tuples, arrays) leave it empty: their
    /// signature is compositional and is not needed to encode.
    const SIGNATURE: &'static str = "";
    /// Alignment of the serialized form, in bytes.
    const ALIGNMENT: usize;
    /// Serialized size if fixed-size, else `None`.
    const FIXED_SIZE: Option<usize>;
}

/// Encode a value into normal-form GVariant bytes.
///
/// `encode` appends this value at the current end of `out`; container impls
/// pad each member to its alignment before delegating, so the top-level call
/// only needs an empty (or already-aligned) buffer.
pub trait GvEncode: GvType {
    /// Append the normal-form serialization of `self` to `out`.
    fn encode(&self, out: &mut Vec<u8>) -> Result<()>;
}

/// Decode normal-form GVariant bytes, borrowing from `data` where possible.
///
/// Scalar, string, tuple, and variant decoders reject any deviation from
/// normal form (nonzero padding, out-of-order offsets, unterminated or
/// non-UTF-8 strings, wrong sizes) at decode time. [`ArrayIter`]'s decode
/// checks the array's outer framing and defers the per-element checks to
/// iteration; draining the iterator applies the same checks as
/// [`from_bytes`](crate::from_bytes).
pub trait GvDecode<'a>: GvType + Sized {
    /// Decode a value from the slice covering exactly its serialized form.
    fn decode(data: &'a [u8]) -> Result<Self>;
}

/// Encode a top-level value to a fresh byte vector.
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

/// Encode an owned string by delegating to the `&str` path, so an owned value
/// (a dirtree entry name, say) can be a tuple or array member without first
/// being reborrowed into a temporary slice of references.
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

/// A lazy reader over the elements of a serialized array. Holds only the
/// backing slice and a cursor, so iteration allocates nothing.
#[derive(Clone, Copy)]
pub(crate) struct ArrayReader<'a> {
    data: &'a [u8],
    elem_alignment: usize,
    /// `Some` for a fixed-size element type; drives the packing/framing split.
    elem_size: Option<usize>,
    /// Framing-offset size (variable-element arrays only).
    z: usize,
    /// End of the element data, where the framing area begins (variable only).
    data_end: usize,
    /// Element count.
    n: usize,
    /// Next element index.
    i: usize,
    /// Current data position (variable-element cursor).
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
        // plus its own offsets. A wider size re-encodes to fewer bytes, so a
        // buffer that would not survive re-encode is rejected here.
        if choose_offset_size(data_end, r.n) != z {
            return Err(Error::NotNormal(
                "array framing offset size is not normal-form",
            ));
        }
        Ok(r)
    }

    /// The full serialized array slice, including the framing area.
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
            // A framing error leaves `pos` unusable; fuse the reader.
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

/// A decoded array: a lazy iterator that decodes one element per step.
///
/// `ArrayIter` borrows the source buffer and yields `Result<E>`, so
/// per-element normal-form checks surface as the elements are visited. It is
/// `Copy`, so it can be re-iterated from the start. A framing error fuses the
/// iterator: the `Err` is yielded once and every following call returns
/// `None`.
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
    /// Re-emit the borrowed array. The reader's backing slice is already
    /// normal-form and, re-placed at the same alignment, reproduces its bytes.
    fn encode(&self, out: &mut Vec<u8>) -> Result<()> {
        out.extend_from_slice(self.reader.bytes());
        Ok(())
    }
}

/// An array to encode from a Rust slice of encodable elements.
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

/// Append `n` array elements with normal-form framing. `write_elem(out, i)`
/// appends element `i`; the caller supplies the element encoding while this
/// function owns the padding and the framing-offset area, so the array rule
/// exists once for both the typed and the `Value` encoders. It is public so a
/// caller with its own element storage (an ostree object's owned field arrays)
/// can emit array framing without first collecting element references.
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
        // Fixed sizes are multiples of the element alignment, so elements pack
        // back to back with no padding and no framing offsets.
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

/// A decoded variant: the child's type and value together with the borrowed
/// child bytes and signature.
///
/// Variants carry a dynamic child type, so [`decode`](GvDecode::decode) parses
/// the child into a [`Value`] once and keeps it; [`Variant::value`] borrows
/// that value without re-walking the bytes or cloning. This is the one building
/// block that allocates on decode; it sits off the traversal hot path (variants
/// appear only inside `a{sv}` metadata). [`encode`](GvEncode::encode) re-emits the
/// borrowed child bytes and signature, so it reproduces the input byte-for-byte
/// without rebuilding the signature string.
pub struct Variant<'a> {
    ty: Type,
    child: &'a [u8],
    signature: &'a [u8],
    value: Value,
}

impl<'a> Variant<'a> {
    /// The child's GVariant type.
    pub fn ty(&self) -> &Type {
        &self.ty
    }

    /// The child payload as a [`Value`], borrowed from the value parsed at
    /// decode time.
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

/// The fixed size of a struct given each member's `(alignment, fixed_size)`,
/// or `None` if any member is variable-size. Matches `Type::fixed_size`.
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

/// A cursor that carves a serialized tuple/dict-entry body into member slices,
/// applying the same framing and padding checks as `from_bytes`.
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
        // With framing offsets present, the offset size must be the one the
        // encoder would pick for this member area; a wider size re-encodes to
        // fewer bytes and is rejected. Fully fixed and last-member-only tuples
        // carry no offsets, so `z` is irrelevant there.
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
/// framing offsets, producing the same bytes as `to_bytes`.
pub(crate) struct TupleWriter<'b> {
    out: &'b mut Vec<u8>,
    start: usize,
    /// End offsets of variable-size members other than the last, in member
    /// order; emitted in reverse by [`finish`](Self::finish).
    offsets: Vec<usize>,
}

impl<'b> TupleWriter<'b> {
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

    /// Append a member with runtime alignment and fixed-size, delegating the
    /// member encoding to `write`. The framing rule lives here for both the
    /// typed and the `Value` encoders.
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
        self.field_dyn(T::ALIGNMENT, T::FIXED_SIZE, is_last, |out| value.encode(out))
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

    /// Round-trip a typed value against `to_bytes`/`from_bytes` for the given
    /// signature: the typed encoding must equal the `Value` encoding, `Value`
    /// decode of those bytes must reproduce `expected_value`, and typed decode
    /// must re-encode to the same bytes.
    ///
    /// The decode-and-re-encode step is supplied as `decode_reencode` so the
    /// borrowed view binds to the locally produced buffer: a borrowed type
    /// such as `&str` cannot be decoded into a fixed lifetime chosen by the
    /// caller, so the closure decodes and re-encodes within a single call.
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
        check("u", &0x0102_0304u32, &Value::U32(0x0102_0304), |b: &[u8]| {
            encode_to_vec(&<u32>::decode(b)?)
        });
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
        check("ay", &bytes, &Value::Bytes(vec![0, 1, 2, 0, 4]), |b: &[u8]| {
            encode_to_vec(&<&[u8]>::decode(b)?)
        });
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
        // (su): string needs a framing offset, the trailing u32 does not.
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
        // A dict entry {sv} carrying a string value, the a{sv} building block.
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
        // (ya(uu)): the leading byte leaves the 4-aligned array preceded by
        // padding, which the re-encode of the borrowed array must reproduce.
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
        // Two-element "as" whose first framing offset exceeds the data area:
        // the framing error surfaces once, then iteration ends.
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
        // Valid outer framing around a corrupt element: decode succeeds and
        // the element error surfaces when the element is visited (D3).
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
        // A 256-byte `as` with one 254-byte string element framed by a 2-byte
        // offset. Normal form uses a 1-byte offset (255 bytes total), so the
        // wider encoding must be rejected rather than decoded and silently
        // re-serialized to shorter, differently-checksummed bytes.
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
        // A 256-byte `(ss)` whose single framing offset is 2 bytes; normal
        // form uses a 1-byte offset (255 bytes total). The member area is the
        // two NUL-terminated strings; the trailing offset points to the end
        // of the first.
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
