
from __future__ import annotations
from typing import TYPE_CHECKING, Iterable, Union

from dragodis.ida.variable import IDAStackVariable, IDA9StackVariable
from dragodis.interface.stack import StackFrame

if TYPE_CHECKING:
    from dragodis.ida.flat import IDAFlatAPI
    import ida_struct
    import ida_typeinf

class IDAStackFrame(StackFrame):

    def __init__(self, ida: IDAFlatAPI, frame: "ida_struct.struc_t"):
        self._ida = ida
        self._frame = frame
        # Obtain the base of the stack by obtaining the location of the return address.
        func = self._ida._ida_funcs.get_func(
            self._ida._ida_frame.get_func_by_frame(self._frame.id)
        )
        self._base_offset = self._ida._ida_frame.frame_off_retaddr(func)
        self._retsize = self._ida._ida_frame.get_frame_retsize(func)

    def __eq__(self, other):
        return self is other or self._frame.id == other._frame.id

    def __getitem__(self, name_or_offset: Union[str, int]) -> IDAStackVariable:
        if isinstance(name_or_offset, int):
            offset = name_or_offset + self._base_offset
            member = self._ida._ida_struct.get_member(self._frame, offset)
        elif isinstance(name_or_offset, str):
            name = name_or_offset
            member = self._ida._ida_struct.get_member_by_name(self._frame, name)
        else:
            raise TypeError(f"Must be str or int, got {type(name_or_offset)}")
        if not member:
            raise KeyError(f"Unable to find stack variable from: {name_or_offset}")
        return IDAStackVariable(self._ida, self, member)

    def __delitem__(self, name_or_offset: Union[str, int]):
        variable = self[name_or_offset]
        self._ida._ida_struct.del_struc_member(self._frame, variable._member.soff)

    def __iter__(self) -> Iterable[IDAStackVariable]:
        for member in self._frame.members:
            variable = IDAStackVariable(self._ida, self, member)
            # Ignore the hidden " s" and " r" variables.
            # TODO: Determine meaning behind these.
            if variable.name not in (" s", " r"):
                yield variable

    def __len__(self) -> int:
        # - 1 for the " s" hidden member and - 1 if there would be a " r" hidden return
        # variable as well.
        return self._frame.memqty - 1 - (1 if self._retsize else 0)

class IDA9StackFrame(IDAStackFrame):
    """
    This class is equivalent to IDAStackFrame except it contains API changes that allow it to work on
    IDA 8.5 and 9.0 + only.
    """

    def __init__(self, ida: IDAFlatAPI, frame: "ida_typeinf.tinfo_t"):
        self._ida = ida
        self._frame = frame
        # Obtain the base of the stack by obtaining the location of the return address.
        func = self._ida._ida_funcs.get_func(
            frame.get_frame_func()
        )
        self._base_offset = self._ida._ida_frame.frame_off_retaddr(func)
        self._retsize = self._ida._ida_frame.get_frame_retsize(func)

    def __eq__(self, other):
        return self is other or self._frame.get_tid() == other._frame.get_tid()

    def __getitem__(self, name_or_offset: Union[str, int]) -> IDAStackVariable:
        if isinstance(name_or_offset, int):
            offset = name_or_offset + self._base_offset
            status, member = self._frame.get_udm_by_offset(offset)
        elif isinstance(name_or_offset, str):
            name = name_or_offset
            status, member = self._frame.get_udm(name)
        else:
            raise TypeError(f"Must be str or int, got {type(name_or_offset)}")
        if status == -1:
            raise KeyError(f"Unable to find stack variable from: {name_or_offset}")
        return IDA9StackVariable(self._ida, self, member)

    def __delitem__(self, name_or_offset: Union[str, int]):
        variable = self[name_or_offset]
        self._frame.del_udms(variable._member_index, variable._member_index)

    def __iter__(self) -> Iterable[IDAStackVariable]:
        for member in self._frame.iter_udt():
            variable = IDA9StackVariable(self._ida, self, member)
            # Ignore the hidden " s" and " r" variables.
            # TODO: Determine meaning behind these.
            if variable.name not in (" s", " r"):
                yield variable

    def __len__(self) -> int:
        # - 1 for the " s" hidden member and - 1 if there would be a " r" hidden return
        # variable as well.
        return self._frame.get_udt_nmembers() - 1 - (1 if self._retsize else 0)
