//
// Copyright (C) 2019, 2020 Signal Messenger, LLC.
// All rights reserved.
//
// SPDX-License-Identifier: AGPL-3.0-or-later
//

use bytes::{Buf};
use num_traits::{ToPrimitive};

const SGX_FLAGS_INITTED:        u64 = 0x0000_0000_0000_0001;
const SGX_FLAGS_DEBUG:          u64 = 0x0000_0000_0000_0002;
const SGX_FLAGS_MODE64BIT:      u64 = 0x0000_0000_0000_0004;
const SGX_FLAGS_RESERVED:       u64 = 0xFFFF_FFFF_FFFF_FFC8;
const SGX_XFRM_RESERVED:        u64 = 0xFFFF_FFFF_FFFF_FFF8;

#[derive(Default)]
pub struct SgxQuote {
    pub version:         u16,
    pub is_sig_linkable: bool,
    pub gid:             u32,
    pub qe_svn:          u16,
    pub pce_svn:         u16,
    pub basename:        [u8; 32],
    pub cpu_svn:         [u8; 16],
    pub flags:           u64,
    pub xfrm:            u64,
    pub mrenclave:       [u8; 32],
    pub mrsigner:        [u8; 32],
    pub isv_prod_id:     u16,
    pub isv_svn:         u16,
    pub report_data:     SgxReportData,
    pub has_signature:   bool,
}

pub struct SgxReportData(pub [u8; 64]);

impl Default for SgxReportData {
    fn default() -> Self {
        Self([0; 64])
    }
}

#[derive(Debug)]
pub enum SgxQuoteDecodeError {
    Truncated(usize),
    NonZeroReserved(usize),
    UnknownVersion(u16),
    UnknownSignType(u16),
    InvalidFlags(u64),
    InvalidXfrm(u64),
    InvalidSignatureLength(u32),
}

impl SgxQuote {
    pub fn decode(quote_buf: &mut impl Buf) -> Result<Self, SgxQuoteDecodeError> {
        if quote_buf.remaining() < 432 {
            return Err(SgxQuoteDecodeError::Truncated(quote_buf.remaining()));
        }

        let mut quote: Self = Default::default();

        quote.version   = quote_buf.get_u16_le();
        if !(quote.version >= 1 && quote.version <= 2) {
            return Err(SgxQuoteDecodeError::UnknownVersion(quote.version));
        }

        let sign_type = quote_buf.get_u16_le();
        if (sign_type & !1) != 0 {
            return Err(SgxQuoteDecodeError::UnknownSignType(sign_type));
        }

        quote.is_sig_linkable = sign_type == 1;
        quote.gid             = quote_buf.get_u32_le();
        quote.qe_svn          = quote_buf.get_u16_le();

        if quote.version > 1 {
            quote.pce_svn = quote_buf.get_u16_le();
        } else {
            Self::read_zero(quote_buf, 10, 2)?;
            quote.pce_svn = 0;
        }

        Self::read_zero(quote_buf, 12, 4)?; // xeid (reserved)
        quote_buf.copy_to_slice(&mut quote.basename);

        //
        // report_body
        //

        quote_buf.copy_to_slice(&mut quote.cpu_svn);
        Self::read_zero(quote_buf, 64, 4)?; // misc_select (reserved)
        Self::read_zero(quote_buf, 68, 28)?; // reserved1

        quote.flags = quote_buf.get_u64_le();
        if ((quote.flags & SGX_FLAGS_RESERVED ) != 0 ||
            (quote.flags & SGX_FLAGS_INITTED  ) == 0 ||
            (quote.flags & SGX_FLAGS_MODE64BIT) == 0)
        {
            return Err(SgxQuoteDecodeError::InvalidFlags(quote.flags));
        }

        quote.xfrm = quote_buf.get_u64_le();
        if (quote.xfrm & SGX_XFRM_RESERVED) != 0 {
            return Err(SgxQuoteDecodeError::InvalidXfrm(quote.xfrm));
        }

        quote_buf.copy_to_slice(&mut quote.mrenclave);
        Self::read_zero(quote_buf, 144, 32)?; // reserved2
        quote_buf.copy_to_slice(&mut quote.mrsigner);
        Self::read_zero(quote_buf, 208, 96)?; // reserved3
        quote.isv_prod_id = quote_buf.get_u16_le();
        quote.isv_svn     = quote_buf.get_u16_le();
        Self::read_zero(quote_buf, 308, 60)?; // reserved4
        quote_buf.copy_to_slice(&mut quote.report_data.0);

        //
        // quote signature
        //

        if quote_buf.remaining() != 0 {
            let signature_length = quote_buf.get_u32_le();
            if quote_buf.remaining().to_u32() != Some(signature_length) {
                return Err(SgxQuoteDecodeError::InvalidSignatureLength(signature_length));
            }
            quote.has_signature = true;
        } else {
            quote.has_signature = false;
        }

        Ok(quote)
    }

    pub fn is_debug_quote(&self) -> bool {
        (self.flags & SGX_FLAGS_DEBUG) != 0
    }

    fn read_zero(buf: &mut impl Buf, pos: usize, count: usize) -> Result<(), SgxQuoteDecodeError> {
        for _ in 0..count {
            if buf.get_u8() != 0 {
                return Err(SgxQuoteDecodeError::NonZeroReserved(pos));
            }
        }
        Ok(())
    }
}
