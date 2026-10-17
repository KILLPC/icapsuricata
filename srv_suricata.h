/*-
 * Suricata ICAP service
 *
 * Copyright (c) 2026, Soner Tari <sonertari@gmail.com>.
 * All rights reserved.
 *
 * You can copy, redistribute or modify this Program under the terms of
 * the GNU General Public License version 2 as published by the Free
 * Software Foundation.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * version 2 along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA
 * 02110-1301, USA.
 */

#ifndef SRV_SURICATA_H
#define SRV_SURICATA_H

#include <c_icap/debug.h>

#define suri_log(LEVEL, format_str, ...) \
    ci_debug_printf(LEVEL, "srv_suricata: %s: " format_str, __FUNCTION__, ##__VA_ARGS__)

#endif /* SRV_SURICATA_H */
