# Visual Analysis of Cyber Threat. Part 2: Cleaning the data
# Serhan Aya 2016-07-01.

# The data acquired in the previous step is clean, but,
# in order to further understand the relationships in the
# data, the columns Name, VDF, AddedOn and DateDiscovered
# are examined.

# Load required packages
library(feather)    # Save/load the dataframe
library(lubridate)  # Date manipulation
library(dplyr)      # Data manipulation
library(stringr)    # String manipulation

# Load the virus information data.
path <- ("data/tVirData.feather")
tVirData <- read_feather(path)

# Create a copy dataframe for exploration/manipulation.
df <- tVirData

# The data in columns AddedOn and DateDiscovered are date type.
df$AddedOn <- mdy(df$AddedOn)
df$DateDiscovered <- mdy(df$DateDiscovered)

# Fill NA's in DateDiscovered column with the data in AddedOn column.
df$DateDiscovered[is.na(df$DateDiscovered)] <-
    df$AddedOn[is.na(df$DateDiscovered)]
# After this, check for similarity.
identical(df$AddedOn, df$DateDiscovered)
# TRUE.

# Remove one of the identical columns.
# From now on DateDiscovered column will be used as a reference of
# both "The date added on the database" and "The date of discovery".
df <- df %>%
    select(-AddedOn)

# Shorten the names of Type.
df$Type[df$Type == "Potential Unwanted Application"] <- "PUA"

# The following line extracts the `Name` column to character clusters
# and saves the result as a matrix.
nameExtract <- str_extract_all(df$Name,"([A-z])\\w+", simplify = TRUE)

# Save the previous result as a dataframe.
nameExtract <- data.frame(nameExtract, stringsAsFactors = FALSE)

# Assign names to this dataframe. This `NExt1..2..3` columns
# represents the variations of the viruses named under `NName` column.
# `NType` column is the prefix which stands for the type of the virus.
# There is another `Type` column exist in the main data frame, but
# `NType` gives additional/detailed information to the `Type` column for
# the type of the virus.
names(nameExtract) <- c("NType", "NName", "NExt1", "NExt2", "NExt3")

# Add column `No` for following `Join` operation.
nameExtract$No <- 1:length(nameExtract$NName)

# Left_join main dataframe with the extracted nameExtract dataframe
# by `No` column.
df <- left_join(df, nameExtract, by="No")

# Extract the IP no-like code and the date from `VDF` column.
# Save `Date` part as `VDFDate` and add to main dataframe.
df$VDFDate <- ymd(str_extract(df$VDF,"\\b\\d{4}\\-\\d{2}\\-\\d{2}"))

# Save `IP no-like code` part as a replacement for the original `VDF`
# column.
df$VDF <- str_extract(df$VDF, "\\b\\d\\.\\d{2}\\.\\d{1,3}\\.\\d{1,3}")

# `trim` function removes the leading and trailing whitespace of a string.
trim <- function (x) gsub("^\\s+|\\s+$", "", x)
df$Impact <- trim(df$Impact)
df$Infections <- trim(df$Infections)

# Create the dataframe to be saved for later use.
tVDClean <- df %>%
    select(No, NName, NExt1, NExt2, NExt3, NType, Type, DateDiscovered,
        VDFDate, Impact, OS, Infections, VDF, Name, Aliases)

# Save the dataframe for later use.
path2 <- "data/tVDClean.feather"
write_feather(tVDClean, path2)
