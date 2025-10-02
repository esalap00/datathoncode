#!/usr/bin/env bash
# procesar_videos.sh
# Uso: ./procesar_videos.sh /ruta/a/carpeta_videos
# - Genera hashes SHA256 en la carpeta original
# - Copia la carpeta a carpeta_copy (si ya existe añade sufijo con timestamp)
# - Genera metadatos JSON por vídeo en la copia (metadatos/)
# - Analiza cada JSON y genera indicadores_sospechosos.txt con name + parámetros

set -euo pipefail

if [ $# -ne 1 ]; then
  echo "Uso: $0 /ruta/a/carpeta_videos"
  exit 1
fi

SRC_DIR="$1"
if [ ! -d "$SRC_DIR" ]; then
  echo "Error: $SRC_DIR no es un directorio válido."
  exit 1
fi

SRC_DIR="${SRC_DIR%/}"   # Normalizar ruta sin slash final

# ========================
# HASHES EN CARPETA ORIGINAL
# ========================
HASH_FILE_ORIG="${SRC_DIR}/hashes_videos.txt"
: > "$HASH_FILE_ORIG"
echo "Generando hashes en la carpeta original: $HASH_FILE_ORIG"

while IFS= read -r -d '' FILE; do
    REL_PATH="${FILE#${SRC_DIR}/}"
    if command -v sha256sum >/dev/null 2>&1; then
        HASH=$(sha256sum "$FILE" | awk '{print $1}')
    else
        HASH=$(sha1sum "$FILE" | awk '{print $1}')
    fi
    echo "${REL_PATH} : ${HASH}" >> "$HASH_FILE_ORIG"
done < <(find "$SRC_DIR" -type f -iname '*.mp4' -print0)

# ========================
# COPIA DE CARPETA
# ========================
DEST_DIR="${SRC_DIR}_copy"
if [ -e "$DEST_DIR" ]; then
  TIMESTAMP=$(date +%Y%m%d_%H%M%S)
  DEST_DIR="${DEST_DIR}_${TIMESTAMP}"
fi

echo "Copiando '$SRC_DIR' -> '$DEST_DIR' ..."
cp -a "$SRC_DIR" "$DEST_DIR"

# Rutas de salida dentro del directorio copia
HASH_FILE="${DEST_DIR}/hashes_videos.txt"
METADATA_DIR="${DEST_DIR}/metadatos"
INDICADORES_FILE="${DEST_DIR}/indicadores_sospechosos.txt"

mkdir -p "$METADATA_DIR"
: > "$HASH_FILE"
: > "$INDICADORES_FILE"

# ========================
# FUNCIONES AVANZADAS
# ========================

check_gop() {
  local file="$1"
  ffprobe -v quiet -select_streams v:0 -show_frames -of csv=p=0 -show_entries frame=pict_type "$file" \
    | awk -F',' '{print $1}' > /tmp/pict_$$.txt
  awk '{ if($1=="I"){print NR} }' /tmp/pict_$$.txt > /tmp/Iidx_$$.txt
  awk 'NR==1{prev=$1;next} {print $1-prev; prev=$1}' /tmp/Iidx_$$.txt > /tmp/goplen_$$.txt
  if [ -s /tmp/goplen_$$.txt ]; then
    mean=$(awk '{sum+=$1; n++} END{ if(n>0) printf "%.2f", sum/n; else print 0}' /tmp/goplen_$$.txt)
    sd=$(awk -v m="$mean" '{sum+=($1-m)^2; n++} END{ if(n>1) printf "%.2f", sqrt(sum/(n-1)); else print 0}' /tmp/goplen_$$.txt)
    echo "GOP_mean:$mean GOP_sd:$sd"
    if (( $(echo "$sd < 2 && $mean>0" | bc -l) )); then
      echo "FLAG: GOP muy regular (posible re-encode/render)"
    fi
  fi
  rm -f /tmp/pict_$$.txt /tmp/Iidx_$$.txt /tmp/goplen_$$.txt
}

check_packet_timing() {
  local file="$1"
  ffprobe -v quiet -select_streams v:0 -show_packets -of csv=p=0 -show_entries packet=pts_time "$file" > /tmp/pts_$$.txt 2>/dev/null
  if ! [ -s /tmp/pts_$$.txt ]; then rm -f /tmp/pts_$$.txt; return; fi
  awk 'NR==1{prev=$1;next} {print $1-prev; prev=$1}' /tmp/pts_$$.txt > /tmp/ptsdiff_$$.txt
  mean=$(awk '{sum+=$1; n++} END{ if(n>0) printf "%.6f", sum/n; else print 0}' /tmp/ptsdiff_$$.txt)
  sd=$(awk -v m="$mean" '{sum+=($1-m)^2; n++} END{ if(n>1) printf "%.6f", sqrt(sum/(n-1)); else print 0}' /tmp/ptsdiff_$$.txt)
  echo "pkt_pts_mean_diff:$mean pkt_pts_sd:$sd"
  if (( $(echo "$sd < 0.0005 || $sd > 0.1" | bc -l) )); then
    echo "FLAG: anomalía en pkt_pts diffs (posible remux/edición)"
  fi
  rm -f /tmp/pts_$$.txt /tmp/ptsdiff_$$.txt
}

check_stream_structure() {
  local jsonfile="$1"
  EXTRADATA=$(jq -r '.streams[0].extradata_size // 0' "$jsonfile")
  NALSIZE=$(jq -r '.streams[0].nal_length_size // 0' "$jsonfile")
  REFS=$(jq -r '.streams[0].refs // 0' "$jsonfile")
  BFRAMES=$(jq -r '.streams[0].has_b_frames // 0' "$jsonfile")
  IS_AVC=$(jq -r '.streams[0].is_avc // "false"' "$jsonfile")
  echo "extradata_size:$EXTRADATA nal_len:$NALSIZE refs:$REFS b_frames:$BFRAMES is_avc:$IS_AVC"
  if [ "$EXTRADATA" -lt 20 ]; then
    echo "FLAG: extradata_size bajo/inexistente (posible remux/sustracción de headers)"
  fi
  if [ "$BFRAMES" -eq 0 ]; then
    echo "NOTE: 0 B-frames (depende del encoder, pero puede indicar reencode)"
  fi
}

check_packet_size_distribution() {
  local file="$1"
  ffprobe -v quiet -select_streams v:0 -show_packets -of csv=p=0 -show_entries packet=size "$file" > /tmp/sizes_$$.txt
  if ! [ -s /tmp/sizes_$$.txt ]; then rm -f /tmp/sizes_$$.txt; return; fi
  mean=$(awk '{sum+=$1; n++} END{ if(n>0) printf "%.2f", sum/n; else print 0}' /tmp/sizes_$$.txt)
  sd=$(awk -v m="$mean" '{sum+=($1-m)^2; n++} END{ if(n>1) printf "%.2f", sqrt(sum/(n-1)); else print 0}' /tmp/sizes_$$.txt)
  echo "pkt_size_mean:$mean pkt_size_sd:$sd"
  if (( $(echo "$sd < 50" | bc -l) )); then
    echo "FLAG: baja desviación en tamaños de paquete (posible render/reencode)"
  fi
  rm -f /tmp/sizes_$$.txt
}

check_audio_stream() {
  local jsonfile="$1"
  if jq -e '.streams[] | select(.codec_type=="audio")' "$jsonfile" >/dev/null 2>&1; then
    A_CODEC=$(jq -r '.streams[] | select(.codec_type=="audio") | .codec_name' "$jsonfile")
    A_RATE=$(jq -r '.streams[] | select(.codec_type=="audio") | .sample_rate' "$jsonfile")
    echo "audio: $A_CODEC rate:$A_RATE"
  else
    echo "FLAG: No hay stream de audio"
  fi
}

# ========================
# HASHES Y METADATOS EN COPIA
# ========================
echo "Generando hashes y metadatos en la copia..."
while IFS= read -r -d '' FILE; do
  REL_PATH="${FILE#${DEST_DIR}/}"
  BASENAME="$(basename "$FILE")"

  echo "Analizando: $REL_PATH"

  # Hash SHA256
  if command -v sha256sum >/dev/null 2>&1; then
    HASH=$(sha256sum "$FILE" | awk '{print $1}')
  else
    HASH=$(sha1sum "$FILE" | awk '{print $1}')
  fi
  echo "${REL_PATH} : ${HASH}" >> "$HASH_FILE"

  # Metadatos JSON
  METADATA_FILE="${METADATA_DIR}/${BASENAME}.json"
  ffprobe -v quiet -print_format json -show_format -show_streams "$FILE" > "$METADATA_FILE" || {
    echo "  !! Error extrayendo metadatos para $REL_PATH" >&2
    continue
  }

done < <(find "$DEST_DIR" -type f -iname '*.mp4' -print0)

# ========================
# ANALISIS DE JSON PARA INDICADORES
# ========================
echo "Análisis de metadatos para detectar indicios de modificación/IA..."
while IFS= read -r -d '' JSONFILE; do
  BASENAME="$(basename "$JSONFILE" .json)"
  VIDEO_REL_PATH="$(find "$DEST_DIR" -type f -iname "${BASENAME}.mp4" -print -quit || true)"
  if [ -z "$VIDEO_REL_PATH" ]; then
    VIDEO_REL_PATH="${BASENAME}.mp4"
  else
    VIDEO_REL_PATH="${VIDEO_REL_PATH#${DEST_DIR}/}"
  fi

  # Extraer campos con jq
  ENCODER=$(jq -r '.format.tags.encoder // empty' "$JSONFILE" 2>/dev/null || echo "")
  VENDOR_ID=$(jq -r '.streams[0].tags.vendor_id // empty' "$JSONFILE" 2>/dev/null || echo "")
  FRAME_RATE=$(jq -r '.streams[0].r_frame_rate // empty' "$JSONFILE" 2>/dev/null || echo "")
  AVG_FRAME_RATE=$(jq -r '.streams[0].avg_frame_rate // empty' "$JSONFILE" 2>/dev/null || echo "")
  BIT_RATE=$(jq -r '.streams[0].bit_rate // empty' "$JSONFILE" 2>/dev/null || echo "")
  NB_FRAMES=$(jq -r '.streams[0].nb_frames // empty' "$JSONFILE" 2>/dev/null || echo "")
  DURATION=$(jq -r '.format.duration // empty' "$JSONFILE" 2>/dev/null || echo "")
  MAKE=$(jq -r '.streams[0].tags.make // empty' "$JSONFILE" 2>/dev/null || echo "")
  MODEL=$(jq -r '.streams[0].tags.model // empty' "$JSONFILE" 2>/dev/null || echo "")
  WRITERA=$(jq -r '.format.tags.writer // empty' "$JSONFILE" 2>/dev/null || echo "")
  WRITING_APP=$(jq -r '.format.tags["encoding_tool"] // .format.tags["writing_application"] // empty' "$JSONFILE" 2>/dev/null || echo "")

  FLAGS=()

  # Indicadores básicos
  if [[ -n "$ENCODER" ]]; then
    if [[ "$ENCODER" == Lavf* ]] || [[ "$ENCODER" == Lavc* ]] || [[ "$ENCODER" == *FFmpeg* ]] || [[ "$ENCODER" == *ffmpeg* ]]; then
      FLAGS+=("Reempaquetado/encode con FFmpeg (encoder: $ENCODER)")
    else
      FLAGS+=("Encoder/reportado: $ENCODER")
    fi
  fi

  if [[ -n "$WRITERA" || -n "$WRITING_APP" ]]; then
    WAPP="${WRITERA:-$WRITING_APP}"
    if echo "$WAPP" | grep -Eiq "runway|synthesia|pictory|descript|stablediffusion|midjourney|dall|openai|gpt|deepfake|deepfacelab|faceapp|aftereffects|premiere|davinci|resample|ffmpeg"; then
      FLAGS+=("Aplicación de escritura/export: $WAPP (posible herramienta de renderizado/IA)")
    else
      FLAGS+=("Aplicación de escritura/export: $WAPP")
    fi
  fi

  if [[ "$VENDOR_ID" == "[0][0][0][0]" || -z "$VENDOR_ID" ]]; then
    FLAGS+=("Sin vendor_id o vendor_id vacío: posible no-procedencia de cámara física")
  fi

  if [[ -z "$MAKE" && -z "$MODEL" ]]; then
    FLAGS+=("Ausencia de Make/Model de cámara en tags (posible render o generación)")
  else
    FLAGS+=("Make: ${MAKE:-(vacío)}, Model: ${MODEL:-(vacío)}")
  fi

  # Framerate sospechoso
  if [[ "$FRAME_RATE" =~ ^(24/1|25/1|30/1|60/1)$ ]]; then
    FLAGS+=("Framerate exacto: $FRAME_RATE (típico de renderización)")
  fi

  # Bitrate
  if [[ -n "$BIT_RATE" && "$BIT_RATE" =~ ^[0-9]+$ ]]; then
    if (( BIT_RATE < 2000000 )); then
      FLAGS+=("Bitrate relativamente bajo/constante: $BIT_RATE (menos de 2 Mbps)")
    else
      FLAGS+=("Bitrate: $BIT_RATE")
    fi
  fi

  if [[ -n "$NB_FRAMES" && -n "$DURATION" ]]; then
    fps_calc=$(awk -v n="$NB_FRAMES" -v d="$DURATION" 'BEGIN{ if (d>0) printf "%.2f", n/d; else print "0" }')
    FLAGS+=("nb_frames: $NB_FRAMES, duration: $DURATION s, fps aprox: $fps_calc")
  fi

  if jq -e 'tostring | test("stable|diffusion|deepfake|synthetic|ai|gpt|dall|midjourney|runway|synthesia|descript|deepfacelab|faceapp|aftereffects|premiere|davinci|resample|ffmpeg"; "i")' "$JSONFILE" >/dev/null 2>&1; then
    FLAGS+=("Palabras clave relacionadas con IA en metadatos/json")
  fi

  # ========================
  # LLAMADA A FUNCIONES AVANZADAS
  # ========================
  GOP_FLAGS=$(check_gop "$DEST_DIR/$VIDEO_REL_PATH" || true)
  [ -n "$GOP_FLAGS" ] && FLAGS+=("$GOP_FLAGS")

  PKT_FLAGS=$(check_packet_timing "$DEST_DIR/$VIDEO_REL_PATH" || true)
  [ -n "$PKT_FLAGS" ] && FLAGS+=("$PKT_FLAGS")

  STREAM_FLAGS=$(check_stream_structure "$JSONFILE" || true)
  [ -n "$STREAM_FLAGS" ] && FLAGS+=("$STREAM_FLAGS")

  PKTSTAT_FLAGS=$(check_packet_size_distribution "$DEST_DIR/$VIDEO_REL_PATH" || true)
  [ -n "$PKTSTAT_FLAGS" ] && FLAGS+=("$PKTSTAT_FLAGS")

  AUDIO_FLAGS=$(check_audio_stream "$JSONFILE" || true)
  [ -n "$AUDIO_FLAGS" ] && FLAGS+=("$AUDIO_FLAGS")

  # ========================
  # VOLCAR FLAGS
  # ========================
  if [ ${#FLAGS[@]} -gt 0 ]; then
    {
      echo "[$VIDEO_REL_PATH]"
      for f in "${FLAGS[@]}"; do
        echo "  - $f"
      done
      echo ""
    } >> "$INDICADORES_FILE"
  fi

done < <(find "$METADATA_DIR" -type f -name '*.json' -print0)

echo "Hecho."
echo "Hashes carpeta original: $HASH_FILE_ORIG"
echo "Hashes copia: $HASH_FILE"
echo "Metadatos JSON: $METADATA_DIR"
echo "Indicadores sospechosos: $INDICADORES_FILE"
