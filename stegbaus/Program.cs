// Author: Brandon Young, Global Security Response Team
// Publication: January 2017
// Description: This will decode data which has been hidden in image files 
// by using img2data.dll

using System;
using System.Drawing;
using System.Drawing.Imaging;
using System.IO;
using System.Runtime.InteropServices;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Runtime;
using System.Runtime.CompilerServices;


namespace StegBaus_decoder
{
    class Program
    {
        public static byte[] ImagesToData(Image[] images)
        {
            MemoryStream memoryStream = new MemoryStream();
            for (int i = 0; i < images.Length; i++)
            {
                Image image = images[i];
                Rectangle rect = new Rectangle(Point.Empty, image.Size);
                MemoryStream memoryStream2 = new MemoryStream();
                image.Save(memoryStream2, ImageFormat.Bmp);
                Bitmap expr_40 = new Bitmap(memoryStream2);
                BitmapData bitmapData = expr_40.LockBits(rect, ImageLockMode.ReadOnly, PixelFormat.Format24bppRgb);
                IntPtr arg_84_0 = new IntPtr(bitmapData.Scan0.ToInt32() + 4);
                byte[] array = new byte[Marshal.ReadInt32(bitmapData.Scan0) + 44];
                Marshal.Copy(arg_84_0, array, 0, array.Length);
                expr_40.UnlockBits(bitmapData);
                memoryStream2.Close();
                memoryStream.Write(array, 0, array.Length);
            }
            memoryStream.Close();
            return memoryStream.ToArray();
        }


        static void Main(string[] args)
        {
            String dir = args[0];
            Image[] images = new Image[7];
            int i = 0;
            for (i = 0; i < images.Length; i++)
            {
                images[i] = Image.FromFile(dir + "ba3923fd" + i + ".png");
            }
            byte[] results;
            results = Program.ImagesToData(images);
            File.WriteAllBytes(dir + "output.bin", results);

        }
    }
}