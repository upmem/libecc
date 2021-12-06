/*
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 * 
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 * 
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston,
 * MA 02110-1301, USA.
 * 
 */
 
#include <linux/ioctl.h>

#define PIM_IOCTL_LOAD_DPU		_IOW('p', 1, pim_params_t *)
#define PIM_IOCTL_GET_DPU_STATUS	_IOW('p', 2, pim_params_t *)
#define PIM_IOCTL_GET_DPU_MRAM		_IOW('p', 3, pim_params_t *)
#define PIM_IOCTL_SHOW_S_MRAM		_IOW('p', 4, pim_params_t *)

typedef struct {
	uint64_t arg1;
	uint64_t arg2;
	uint64_t ret0;
	uint64_t ret1;
} pim_params_t;

