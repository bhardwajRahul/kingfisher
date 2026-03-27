FROM gcr.io/oss-fuzz-base/base-builder-rust@sha256:c0f40c4bfbcdfff147e0b8b6f1b1026d5d5144865e514261ad05560b38e6270e

COPY . $SRC/kingfisher
COPY .clusterfuzzlite/build.sh $SRC/build.sh
WORKDIR $SRC/kingfisher
