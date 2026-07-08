
//** Introduction
// This file is used to provide the things needed by a module that uses the marshaling
// functions. It handles the variations between the marshaling choices (procedural or
// table-driven).

#if TABLE_DRIVEN_MARSHAL

#  include "TableMarshalTypes.h"

#  include "TableMarshalDefines.h"

#  include "TableDrivenMarshal_fp.h"

#else

#  include "Marshal_fp.h"

#endif
