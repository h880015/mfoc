#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>

#include <unistd.h>

#define INPUT_BUF_SIZE			256
#define MAX_INPUT_BYTES			4
#define ORIG_ACC_BYTE_COUNT		3

#define IDX_ACC_DATA_0			0
#define IDX_ACC_DATA_1			1
#define IDX_ACC_DATA_2			2
#define IDX_ACC_SECTOR_TRAILER	3
#define IDX_ACC_MAX				4

static uint8_t gAccBits[ MAX_INPUT_BYTES ] = { 0 };

static void print_access_bits( const uint8_t *access_bits )
{
	uint32_t	i;

	printf( "Access Bits = " );
	for( i = 0; i < ORIG_ACC_BYTE_COUNT; i ++ )
	{
		printf( "%02X ", access_bits[i] );
	}
	printf( "\n" );
}

static bool check_access_bits( const uint8_t c1, const uint8_t c2, const uint8_t c3, const uint8_t c1_inv, const uint8_t c2_inv, const uint8_t c3_inv )
{
	bool result = true;

	if( (c1 & 0x0F) != ((~c1_inv) & 0x0F) )
	{
		printf( "[W] C1 != ~C1_INV\n" );
		result = false;
	}

	if( (c2 & 0x0F) != ((~c2_inv) & 0x0F) )
	{
		printf( "[W] C2 != ~C2_INV\n" );
		result = false;
	}

	if( (c3 & 0x0F) != ((~c3_inv) & 0x0F) )
	{
		printf( "[W] C3 != ~C3_INV\n" );
		result = false;
	}

	return result;
}

static bool rebuild_access_bits( const uint8_t *access_bits, uint8_t *block_acc )
{
	uint8_t c1, c2, c3, c1_inv, c2_inv, c3_inv;

	c1 = (access_bits[1] >> 4) & 0x0F;
	c2 = (access_bits[2]) & 0x0F;
	c3 = (access_bits[2] >> 4) & 0x0F;
	c1_inv = (access_bits[0]) & 0x0F;
	c2_inv = (access_bits[0] >> 4) & 0x0F;
	c3_inv = (access_bits[1]) & 0x0F;
	
	if( !check_access_bits( c1, c2, c3, c1_inv, c2_inv, c3_inv ) )
		return false;

	block_acc[0] = ((c1 & 1) << 2) | ((c2 & 1) << 1) | ((c3 & 1)     );
	block_acc[1] = ((c1 & 2) << 1) | ((c2 & 2)     ) | ((c3 & 2) >> 1);
	block_acc[2] = ((c1 & 4)     ) | ((c2 & 4) >> 1) | ((c3 & 4) >> 2);
	block_acc[3] = ((c1 & 8) >> 1) | ((c2 & 8) >> 2) | ((c3 & 8) >> 3);

	return true;
}

#define		BLOCK_FORMAT_STRING		"[%c]   %-7s%-7s%-7s%-7s\n"
#define		TRAILER_FORMAT_STRING	"     %-8s%-8s%-8s%-8s%-8s%-8s\n"

static void print_block_acc( const uint8_t *block_acc )
{
	uint32_t	i;

	printf( "\n             Read   Write  Inc    Dec/Xfer/Restore\n" );
	for( i = 0; i < IDX_ACC_SECTOR_TRAILER; i ++ )
	{
		printf( "Block %d ", i );
		switch( block_acc[i] )
		{
		case 0:
			printf( BLOCK_FORMAT_STRING, 'T', "AB", "AB", "AB", "AB" );
			break;
		case 1:
			printf( BLOCK_FORMAT_STRING, 'V', "AB", "--", "--", "AB" );
			break;
		case 2:
			printf( BLOCK_FORMAT_STRING, 'B', "AB", "--", "--", "--" );
			break;
		case 3:
			printf( BLOCK_FORMAT_STRING, 'B', "-B", "-B", "--", "--" );
			break;
		case 4:
			printf( BLOCK_FORMAT_STRING, 'B', "AB", "-B", "--", "--" );
			break;
		case 5:
			printf( BLOCK_FORMAT_STRING, 'B', "-B", "--", "--", "--" );
			break;
		case 6:
			printf( BLOCK_FORMAT_STRING, 'V', "AB", "-B", "-B", "AB" );
			break;
		case 7:
			printf( BLOCK_FORMAT_STRING, 'B', "--", "--", "--", "--" );
			break;
		default:
			break;
		}
	}

	printf( "\nSector Trailer\n    KEYA/R  KEYA/W  ACC/R   ACC/W   KEYB/R  KEYB/W\n" );
	switch( block_acc[ IDX_ACC_SECTOR_TRAILER ] )
	{
		case 0:
			printf( TRAILER_FORMAT_STRING, "--", "A-", "A-", "--", "A-", "A-" );
			break;
		case 1:
			printf( TRAILER_FORMAT_STRING, "--", "A-", "A-", "A-", "A-", "A-" );
			break;
		case 2:
			printf( TRAILER_FORMAT_STRING, "--", "--", "A-", "--", "A-", "--" );
			break;
		case 3:
			printf( TRAILER_FORMAT_STRING, "--", "-B", "AB", "-B", "--", "-B" );
			break;
		case 4:
			printf( TRAILER_FORMAT_STRING, "--", "-B", "AB", "--", "--", "-B" );
			break;
		case 5:
			printf( TRAILER_FORMAT_STRING, "--", "--", "AB", "-B", "--", "--" );
			break;
		case 6:
			printf( TRAILER_FORMAT_STRING, "--", "--", "AB", "--", "--", "--" );
			break;
		case 7:
			printf( TRAILER_FORMAT_STRING, "--", "--", "AB", "--", "--", "--" );
			break;
		default:
			break;
	}
}

void nfc_mifare_decode_access_bits( const uint8_t *access_bits )
{
	uint8_t		block_acc[ IDX_ACC_MAX ];

	print_access_bits( access_bits );
	if( rebuild_access_bits( access_bits, block_acc ) )
	{
		print_block_acc( block_acc );
	}
}

#define	TMP_BUF_SIZE	4

void ConvertAccBits( const uint8_t *strBuf )
{
	uint32_t value;
	char buf[ TMP_BUF_SIZE ] = { 0 };
	uint32_t i;
	for( i = 0; i < MAX_INPUT_BYTES; i ++ )
	{
		if( strBuf[i*2] )
			buf[0] = strBuf[i*2];
		else
			break;

		buf[1] = strBuf[i*2+1];
		buf[2] = '\0';

		value = strtol( buf, NULL, 16 );
		gAccBits[i] = value;
	}
}

void GetAccBits( void )
{
	uint8_t buf[ INPUT_BUF_SIZE ];
	uint8_t accBuf[ ORIG_ACC_BYTE_COUNT * 2 + 1 ] = { 0 };
	uint32_t idxBuf;
	uint32_t idxAcc;
	bool bDone = false;

	do
	{
		printf( "Enter ACC Bits in hex: " );
		fgets( (char *)buf, INPUT_BUF_SIZE, stdin );

		idxBuf = 0;
		idxAcc = 0;
		while( buf[ idxBuf ] != '\0' )
		{
			if( (buf[idxBuf] >= '0' && buf[idxBuf] <= '9') || (buf[idxBuf] >= 'a' && buf[idxBuf] <= 'f') || (buf[idxBuf] >= 'A' && buf[idxBuf] <= 'F') )
			{
				accBuf[ idxAcc ] = buf[ idxBuf ];
				idxAcc ++;
			}
			else if( buf[idxBuf] != ' ' && buf[idxBuf] != '\n' )
			{
				printf( "  (Got invalid character: %c)\n", buf[idxBuf] );
				break;
			}

			if( idxAcc >= ORIG_ACC_BYTE_COUNT * 2 )
			{
				bDone = true;
				break;
			}

			idxBuf ++;
		}
	} while( !bDone );

	ConvertAccBits( accBuf );
}

int main(int argc, char *const argv[])
{
	if( argc > 1 )
	{
		ConvertAccBits( (const uint8_t *)argv[1] );
	}
	else
	{
		GetAccBits();
	}

	nfc_mifare_decode_access_bits( gAccBits );

	return 0;
}
