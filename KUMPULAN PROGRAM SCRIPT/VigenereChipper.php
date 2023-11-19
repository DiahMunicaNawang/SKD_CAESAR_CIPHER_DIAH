<?php

// membuat fungsi enkripsi
function encrypt($key, $text)
{
	// change key to lowercase for simplicity
	$key = strtolower($key);
	
	// inisialisasi variable
	$code = "";
	$ki = 0;
	$kl = strlen($key);
	$length = strlen($text);
	
	// lakukan perulangan untuk setiap abjad
	for ($i = 0; $i < $length; $i++)
	{
		// jika text merupakan alphabet
		if (ctype_alpha($text[$i]))
		{
			// jika text merupakan huruf kapital (semua)
			if (ctype_upper($text[$i]))
			{
				$text[$i] = chr(((ord($key[$ki]) - ord("a") + ord($text[$i]) - ord("A")) % 26) + ord("A"));
			}
			
			// jika text merupakan huruf kecil (semua)
			else
			{
				$text[$i] = chr(((ord($key[$ki]) - ord("a") + ord($text[$i]) - ord("a")) % 26) + ord("a"));
			}
			
			// update the index of key
			$ki++;
			if ($ki >= $kl)
			{
				$ki = 0;
			}
		}
	}
	
	// mengembalikan nilai text
	return $text;
}

// membuat fungsi dekripsi
function decrypt($key, $text)
{
	// change key to lowercase for simplicity
	$key = strtolower($key);
	
	// inisialisasi variable
	$code = "";
	$ki = 0;
	$kl = strlen($key);
	$length = strlen($text);
	
	// lakukan perulangan untuk setiap abjad
	for ($i = 0; $i < $length; $i++)
	{
		// jika text merupakan alphabet
		if (ctype_alpha($text[$i]))
		{
			// jika text merupakan huruf kapital (semua)
			if (ctype_upper($text[$i]))
			{
				$x = (ord($text[$i]) - ord("A")) - (ord($key[$ki]) - ord("a"));
				
				if ($x < 0)
				{
					$x += 26;
				}
				
				$x = $x + ord("A");
				
				$text[$i] = chr($x);
			}
			
			// jika text merupakan huruf kecil (semua)
			else
			{
				$x = (ord($text[$i]) - ord("a")) - (ord($key[$ki]) - ord("a"));
				
				if ($x < 0)
				{
					$x += 26;
				}
				
				$x = $x + ord("a");
				
				$text[$i] = chr($x);
			}
			
			// update the index of key
			$ki++;
			if ($ki >= $kl)
			{
				$ki = 0;
			}
		}
	}
	
	// mengembalikan nilai text
	return $text;
}

?>