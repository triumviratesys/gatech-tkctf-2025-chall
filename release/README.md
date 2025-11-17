# Retrocausality - Decimal Labyrinth

## Challenge Description

Enter the Decimal Labyrinth, a Numogram-based time manipulation system consisting of ten zones (0-9) organized into syzygies (paired by nine-sum twinning). The system manages temporal zones through three interconnected time-systems: Warp, Time-Circuit, and Plex.

Your goal is to achieve "retrocausal breach" by exploiting the system's temporal manipulation capabilities.

## Challenge Details

- **Category**: Binary Exploitation (Heap)
- **Difficulty**: Hard
- **Target**: glibc 2.27, x86-64
- **Protections**: PIE, Full RELRO, NX, ASLR

## Connection Information

```bash
nc <host> <port>
```

## Files Provided

- `target` - The challenge binary
- `README.md` - This file
- `NUMOGRAM.txt` - Visualization of the zone topology

## System Operations

The Decimal Labyrinth supports the following operations:

1. **Manifest Zone** - Create a new zone (0-9)
2. **Inscribe Data** - Write data to a zone
3. **View Zone** - Examine zone contents and metadata
4. **Corrupt Zone** - Enable special capabilities on a zone
5. **Liberate Zone** - Release a zone from temporal constraints
6. **Execute Timeline** - Trigger the final timeline collapse

## The Numogram

The ten zones are organized into five syzygies (paired opposites that sum to 9):

- **Syzygy 0**: Zones 0 & 9 (Warp - Upper time-system)
- **Syzygy 1**: Zones 1 & 8 (Time-Circuit)
- **Syzygy 2**: Zones 2 & 7 (Time-Circuit)
- **Syzygy 3**: Zones 4 & 5 (Time-Circuit)
- **Syzygy 4**: Zones 3 & 6 (Plex - Lower time-system)

See NUMOGRAM.txt for a detailed visualization.

## Hints

- The Plex (zones 3 & 6) conceals a cryptic relationship
- Temporal corruption affects adjacent zones
- Retrocausality operates backward through zone relationships
- Zone 9 contains the Timeline Executor
- Liberation triggers consolidation across temporal boundaries

## References

- CCRU - Writings 1997-2003
- glibc heap exploitation techniques
- House of Einherjar attack method

Good luck navigating the labyrinth!