# Reorder Driver

## Usage
``` sh
    ./benchdnn --reorder [benchdnn-knobs] [reorder-knobs] [reorder-desc] ...
```

where *reorder-knobs* are:

 - `--sdt={f32 [default], s32, s8, u8, bf16, f16}` -- src data type.
            Refer to [data types](knobs_dt.md) for details.
 - `--ddt={f32 [default], s32, s8, u8, bf16, f16}` -- dst data type.
            Refer to [data types](knobs_dt.md) for details.
 - `--stag={nchw [default], ...}` -- physical src memory layout.
            Refer to [tags](knobs_tag.md) for details.
 - `--dtag={nchw [default], ...}` -- physical dst memory layout.
            Refer to [tags](knobs_tag.md) for details.
 - `--attr-oscale=STRING` -- output scale primitive attribute. No oscale is
            set by default. Refer to [attributes](knobs_attr.md) for details.
 - `--attr-zero-points=STRING` -- zero points primitive attribute. No zero
            points are set by default. Refer to [attributes](knobs_attr.md)
            for details.
 - `--attr-post-ops=STRING` -- post operation primitive attribute. No post
            operations are set by default. Refer to [attributes](knobs_attr.md)
            for details.
 - `--def-scales={N1[,N2][,N3]...}` -- input scales, separated by ','.
            Example: 0.125, 0.25, 0.5, 1, 2, 4, 8
 - `--oflag=FLAG:MASK[+...]` -- memory descriptor extra field specifier. By
            default `FLAG` is empty and `MASK` is `0`. Possible `FLAG` values
            are:
            `s8s8_comp` for `compensation_conv_s8s8` flag;
            `zp_comp` for `compensation_conv_asymmetric_src` flag;
            `MASK` value is a non-negative integer number.
 - `--cross-engine={none [default], cpu2gpu, gpu2cpu}` -- defines what kind of
            cross-engine reorder will be used. If `--engine` is set to `cpu`,
            `none` is the only supported value.

and *reorder-desc* is a problem descriptor. The canonical form is:
```
    NxNxNxNxN
```
where N is an integer number. This represents a 3D spatial problem with the
following logical dimensions: N, C, D, H, W. Consider removing each `xN` from
the end to specify fewer dimensions.


## Essence of Testing
TBA.


## Examples

Run the reorder set from an input file with the default settings:
``` sh
    ./benchdnn --reorder --batch=inputs/reorder/test_reorder_all
```

Run two specific reorders with s8 src and dst data type, and specific input and
output physical memory layouts. First problem without a flag; second problem
with the `s8s8_comp` flag and mask of `1`:
``` sh
    ./benchdnn --reorder --sdt=s8 --ddt=s8 --stag=hwio --dtag=OIhw4i16o4i \
               32x32x3x3 \
               --oflag=s8s8_comp:1 16x32x7x5
```

More examples with different driver options can be found at
inputs/reorder/test_***. Examples with different problem descriptors can be
found at inputs/reorder/harness_*** and inputs/reorder/test_***. Examples with
different benchdnn common options can be found at driver_conv.md.
